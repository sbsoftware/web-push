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
    private AES_GCM_TAG_BYTES              = 16
    private RECORD_SEQUENCE_BYTES          =  6
    private MAX_RECORD_SEQUENCE            = (1_u64 << (RECORD_SEQUENCE_BYTES * 8)) - 1_u64
    private MIN_RECORD_SIZE                = AES_GCM_TAG_BYTES + 2
    private DEFAULT_RECORD_SIZE            = 4096
    private HKDF_MAX_OUTPUT_BYTES          = SHA256_BYTES * 255
    private BASE64URL_PATTERN              = /\A[A-Za-z0-9_-]+={0,2}\z/
    private CONTENT_ENCRYPTION_KEY_INFO    = "Content-Encoding: aes128gcm\0".to_slice
    private NONCE_INFO                     = "Content-Encoding: nonce\0".to_slice
    private WEB_PUSH_INFO_PREFIX           = "WebPush: info\0".to_slice
    private AES_128_GCM                    = "aes-128-gcm"
    private EVP_CTRL_AEAD_SET_IVLEN        =  0x9
    private EVP_CTRL_AEAD_GET_TAG          = 0x10

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

    private def self.encrypt_payload_body(subscription : Subscription, payload : String, sender_public_key : String, sender_private_key : String, salt : String, record_size : Int32 = DEFAULT_RECORD_SIZE) : Bytes
      raise ValidationError.new("Push encryption payload must not be empty") if payload.empty?
      frame_payload_records(payload.to_slice, derive_key_schedule(subscription, sender_public_key, sender_private_key, salt), decode_fixed_length_key("salt", salt, SALT_BYTES), decode_p256_public_key("sender_public_key", sender_public_key), record_size)
    end

    private def self.frame_payload_records(payload : Bytes, key_material : KeyMaterial, salt : Bytes, sender_public_key : Bytes, record_size : Int32) : Bytes
      raise ValidationError.new("Push encryption salt must be 16 bytes") unless salt.size == SALT_BYTES
      raise ValidationError.new("Push encryption sender public key must be at most 255 bytes") if sender_public_key.size > 255

      max_record_payload_bytes = validate_record_size(record_size)
      body = IO::Memory.new(payload.size + salt.size + sender_public_key.size + 5)
      body.write(salt)
      body.write_bytes(record_size.to_u32, IO::ByteFormat::BigEndian)
      body.write_byte(sender_public_key.size.to_u8)
      body.write(sender_public_key)

      offset = 0
      sequence_number = 0_u64
      # Records carry delimiter bytes in plaintext: 0x01 for continuation, 0x02 for final.
      while offset < payload.size
        record_payload_size = payload.size - offset > max_record_payload_bytes ? max_record_payload_bytes : payload.size - offset
        plaintext_record = Bytes.new(record_payload_size + 1)
        plaintext_record[0, record_payload_size].copy_from(payload.to_unsafe + offset, record_payload_size)
        plaintext_record[record_payload_size] = offset + record_payload_size == payload.size ? 0x02_u8 : 0x01_u8
        body.write(aes128gcm_encrypt(plaintext_record, key_material.content_encryption_key, record_nonce(key_material.nonce, sequence_number)))
        offset += record_payload_size
        sequence_number += 1_u64
      end

      body.to_slice
    end

    private def self.record_nonce(base_nonce : Bytes, sequence_number : UInt64) : Bytes
      raise ValidationError.new("Push encryption nonce must be 12 bytes") unless base_nonce.size == NONCE_BYTES
      raise ValidationError.new("Push encryption record sequence exceeds 48-bit limit") if sequence_number > MAX_RECORD_SEQUENCE

      nonce = base_nonce.dup
      RECORD_SEQUENCE_BYTES.times { |index| nonce[NONCE_BYTES - 1 - index] ^= ((sequence_number >> (index * 8)) & 0xff_u64).to_u8 }
      nonce
    end

    private def self.aes128gcm_encrypt(plaintext : Bytes, content_encryption_key : Bytes, nonce : Bytes) : Bytes
      raise ValidationError.new("Push encryption content encryption key must be 16 bytes") unless content_encryption_key.size == CONTENT_ENCRYPTION_KEY_BYTES
      raise ValidationError.new("Push encryption nonce must be 12 bytes") unless nonce.size == NONCE_BYTES
      cipher_context = Pointer(Void).null.as(LibCrypto::EVP_CIPHER_CTX)

      cipher_context = LibCrypto.evp_cipher_ctx_new
      raise ValidationError.new("Failed to allocate AES-128-GCM context") if cipher_context.null?
      cipher = LibCrypto.evp_get_cipherbyname(AES_128_GCM)
      raise ValidationError.new("Failed to resolve AES-128-GCM cipher") if cipher.null?
      raise ValidationError.new("Failed to initialize AES-128-GCM cipher") unless LibCrypto.evp_cipherinit_ex(cipher_context, cipher, Pointer(Void).null, Pointer(UInt8).null, Pointer(UInt8).null, 1) == 1
      raise ValidationError.new("Failed to configure AES-128-GCM nonce length") unless LibCrypto.evp_cipher_ctx_ctrl(cipher_context, EVP_CTRL_AEAD_SET_IVLEN, NONCE_BYTES, Pointer(Void).null) == 1
      raise ValidationError.new("Failed to set AES-128-GCM key/nonce") unless LibCrypto.evp_cipherinit_ex(cipher_context, Pointer(Void).null, Pointer(Void).null, content_encryption_key.to_unsafe, nonce.to_unsafe, 1) == 1

      ciphertext = Bytes.new(plaintext.size)
      ciphertext_size = 0
      raise ValidationError.new("Failed to encrypt AES-128-GCM payload") unless LibCrypto.evp_cipherupdate(cipher_context, ciphertext.to_unsafe, pointerof(ciphertext_size), plaintext.to_unsafe, plaintext.size) == 1
      final = Bytes.new(AES_GCM_TAG_BYTES)
      final_size = 0
      raise ValidationError.new("Failed to finalize AES-128-GCM payload") unless LibCrypto.evp_cipherfinal_ex(cipher_context, final.to_unsafe, pointerof(final_size)) == 1
      tag = Bytes.new(AES_GCM_TAG_BYTES)
      raise ValidationError.new("Failed to fetch AES-128-GCM authentication tag") unless LibCrypto.evp_cipher_ctx_ctrl(cipher_context, EVP_CTRL_AEAD_GET_TAG, tag.size, tag.to_unsafe.as(Void*)) == 1

      encrypted_payload = Bytes.new(ciphertext_size + final_size + tag.size)
      encrypted_payload[0, ciphertext_size].copy_from(ciphertext.to_unsafe, ciphertext_size)
      encrypted_payload[ciphertext_size, final_size].copy_from(final.to_unsafe, final_size)
      encrypted_payload[ciphertext_size + final_size, tag.size].copy_from(tag.to_unsafe, tag.size)
      encrypted_payload
    ensure
      LibCrypto.evp_cipher_ctx_free(cipher_context) if cipher_context && !cipher_context.null?
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

    private def self.validate_record_size(record_size : Int32) : Int32
      raise ValidationError.new("Push encryption record size must be at least #{MIN_RECORD_SIZE} bytes") if record_size < MIN_RECORD_SIZE
      record_size - AES_GCM_TAG_BYTES - 1
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
  fun evp_cipher_ctx_ctrl = EVP_CIPHER_CTX_ctrl(ctx : EVP_CIPHER_CTX, type : Int32, arg : Int32, ptr : Void*) : Int32
end
