require "base64"
require "openssl/hmac"

module WebPush
  module RequestBuilder
    private SHA256_BYTES                   = 32
    private P256_PRIVATE_KEY_BYTES         = 32
    private P256_UNCOMPRESSED_PUBLIC_BYTES = 65
    private AUTH_SECRET_BYTES              = 16
    private SALT_BYTES                     = 16
    private CONTENT_ENCRYPTION_KEY_BYTES   = 16
    private NONCE_BYTES                    = 12
    private HKDF_MAX_OUTPUT_BYTES          = SHA256_BYTES * 255
    private BASE64URL_PATTERN              = /\A[A-Za-z0-9_-]+={0,2}\z/
    private CONTENT_ENCRYPTION_KEY_INFO    = "Content-Encoding: aes128gcm\0".to_slice
    private NONCE_INFO                     = "Content-Encoding: nonce\0".to_slice
    private WEB_PUSH_INFO_PREFIX           = "WebPush: info\0".to_slice

    private struct KeyMaterial
      getter content_encryption_key : Bytes
      getter nonce : Bytes

      def initialize(@content_encryption_key : Bytes, @nonce : Bytes)
      end
    end

    private def self.derive_key_schedule(subscription : Subscription, sender_public_key : String, sender_private_key : String, salt : String) : KeyMaterial
      receiver_public_key = decode_p256_public_key("subscription.p256dh", subscription.p256dh)
      auth_secret = decode_fixed_length_key("subscription.auth", subscription.auth, AUTH_SECRET_BYTES)
      sender_public_key_bytes = decode_p256_public_key("sender_public_key", sender_public_key)
      sender_private_key_bytes = decode_fixed_length_key("sender_private_key", sender_private_key, P256_PRIVATE_KEY_BYTES)
      salt_bytes = decode_fixed_length_key("salt", salt, SALT_BYTES)
      shared_secret = ecdh_shared_secret(sender_private_key_bytes, sender_public_key_bytes, receiver_public_key)
      prk = hkdf_extract(salt_bytes, hkdf_expand(hkdf_extract(auth_secret, shared_secret), web_push_info(receiver_public_key, sender_public_key_bytes), SHA256_BYTES))
      KeyMaterial.new(content_encryption_key: hkdf_expand(prk, CONTENT_ENCRYPTION_KEY_INFO, CONTENT_ENCRYPTION_KEY_BYTES), nonce: hkdf_expand(prk, NONCE_INFO, NONCE_BYTES))
    end

    private def self.ecdh_shared_secret(sender_private_key : Bytes, sender_public_key : Bytes, receiver_public_key : Bytes) : Bytes
      sender_key = Pointer(Void).null.as(LibCrypto::EC_KEY)
      sender_private_bn = Pointer(Void).null.as(LibCrypto::BIGNUM)
      sender_public_point = Pointer(Void).null.as(LibCrypto::EC_POINT)
      receiver_public_point = Pointer(Void).null.as(LibCrypto::EC_POINT)

      sender_key = LibCrypto.ec_key_new_by_curve_name(LibCrypto::NID_X9_62_prime256v1)
      raise ValidationError.new("Failed to initialize P-256 key agreement") if sender_key.null?

      sender_private_bn = LibCrypto.bn_bin2bn(sender_private_key.to_unsafe, sender_private_key.size, Pointer(Void).null.as(LibCrypto::BIGNUM))
      raise ValidationError.new("Push encryption field 'sender_private_key' is invalid") if sender_private_bn.null?
      raise ValidationError.new("Push encryption field 'sender_private_key' is invalid") unless LibCrypto.ec_key_set_private_key(sender_key, sender_private_bn) == 1

      group = LibCrypto.ec_key_get0_group(sender_key)
      raise ValidationError.new("Failed to access P-256 key agreement group") if group.null?

      sender_public_point = LibCrypto.ec_point_new(group)
      raise ValidationError.new("Failed to allocate sender public key point") if sender_public_point.null?
      raise ValidationError.new("Push encryption field 'sender_public_key' is invalid") unless LibCrypto.ec_point_oct2point(group, sender_public_point, sender_public_key.to_unsafe, sender_public_key.size, Pointer(Void).null) == 1
      raise ValidationError.new("Push encryption field 'sender_public_key' is invalid") unless LibCrypto.ec_key_set_public_key(sender_key, sender_public_point) == 1
      raise ValidationError.new("Push encryption sender key material is invalid") unless LibCrypto.ec_key_check_key(sender_key) == 1

      receiver_public_point = LibCrypto.ec_point_new(group)
      raise ValidationError.new("Failed to allocate receiver public key point") if receiver_public_point.null?
      raise ValidationError.new("Push encryption field 'subscription.p256dh' is invalid") unless LibCrypto.ec_point_oct2point(group, receiver_public_point, receiver_public_key.to_unsafe, receiver_public_key.size, Pointer(Void).null) == 1

      shared_secret = Bytes.new(P256_PRIVATE_KEY_BYTES)
      shared_secret_size = LibCrypto.ecdh_compute_key(shared_secret.to_unsafe, shared_secret.size, receiver_public_point, sender_key, Pointer(Void).null)
      raise ValidationError.new("Push encryption key agreement failed") unless shared_secret_size == P256_PRIVATE_KEY_BYTES
      shared_secret
    ensure
      LibCrypto.ec_key_free(sender_key) if sender_key && !sender_key.null?
      LibCrypto.bn_free(sender_private_bn) if sender_private_bn && !sender_private_bn.null?
      LibCrypto.ec_point_free(sender_public_point) if sender_public_point && !sender_public_point.null?
      LibCrypto.ec_point_free(receiver_public_point) if receiver_public_point && !receiver_public_point.null?
    end

    private def self.hkdf_extract(salt : Bytes, input_key_material : Bytes) : Bytes
      OpenSSL::HMAC.digest(:sha256, salt, input_key_material)
    end

    private def self.hkdf_expand(prk : Bytes, info : Bytes, output_size : Int32) : Bytes
      raise ValidationError.new("Push encryption HKDF PRK must be 32 bytes") unless prk.size == SHA256_BYTES
      raise ValidationError.new("Push encryption HKDF output length must be between 1 and #{HKDF_MAX_OUTPUT_BYTES} bytes") unless output_size > 0 && output_size <= HKDF_MAX_OUTPUT_BYTES

      output = Bytes.new(output_size)
      offset = 0
      previous_block = Bytes.empty
      counter = 1_u8

      # RFC5869 expand chains each block with the previous block and a one-byte counter.
      while offset < output_size
        input = IO::Memory.new(previous_block.size + info.size + 1)
        input.write(previous_block)
        input.write(info)
        input.write_byte(counter)
        previous_block = OpenSSL::HMAC.digest(:sha256, prk, input.to_slice)

        bytes_to_copy = previous_block.size < output_size - offset ? previous_block.size : output_size - offset
        (output.to_unsafe + offset).copy_from(previous_block.to_unsafe, bytes_to_copy)
        offset += bytes_to_copy
        counter &+= 1
      end

      output
    end

    private def self.web_push_info(receiver_public_key : Bytes, sender_public_key : Bytes) : Bytes
      info = IO::Memory.new(WEB_PUSH_INFO_PREFIX.size + receiver_public_key.size + sender_public_key.size)
      info.write(WEB_PUSH_INFO_PREFIX)
      info.write(receiver_public_key)
      info.write(sender_public_key)
      info.to_slice
    end

    private def self.decode_p256_public_key(field : String, value : String) : Bytes
      decoded = decode_fixed_length_key(field, value, P256_UNCOMPRESSED_PUBLIC_BYTES)
      raise ValidationError.new("Push encryption field '#{field}' must be an uncompressed P-256 key") unless decoded[0] == 0x04
      decoded
    end

    private def self.decode_fixed_length_key(field : String, value : String, expected_size : Int32) : Bytes
      decoded = decode_base64url(field, value)
      raise ValidationError.new("Push encryption field '#{field}' must decode to #{expected_size} bytes") unless decoded.size == expected_size
      decoded
    end

    private def self.decode_base64url(field : String, value : String) : Bytes
      raise ValidationError.new("Push encryption field '#{field}' must be base64url encoded") unless BASE64URL_PATTERN.matches?(value)
      Base64.decode(value)
    rescue ex : Base64::Error
      raise ValidationError.new("Push encryption field '#{field}' must be base64url encoded: #{ex.message}")
    end
  end
end

lib LibCrypto
  fun ecdh_compute_key = ECDH_compute_key(out : UInt8*, outlen : SizeT, pub_key : EC_POINT, ecdh : EC_KEY, kdf : Void*) : Int32
end
