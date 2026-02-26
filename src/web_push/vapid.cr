require "base64"
require "digest/sha256"
require "json"
require "uri"

module WebPush
  # VAPID JWT and header helpers for Web Push requests.
  module Vapid
    DEFAULT_EXPIRATION  = 12.hours
    MAX_EXPIRATION      = 24.hours
    ES256_SIGNATURE_LEN = 64

    private BASE64URL_PATTERN = /\A[A-Za-z0-9_-]+={0,2}\z/

    struct AuthHeaders
      getter authorization : String
      getter crypto_key : String

      def initialize(@authorization : String, @crypto_key : String)
      end
    end

    # Builds a signed VAPID JWT (`ES256`) for the given audience origin.
    #
    # Raises `ValidationError` when audience or expiration is invalid, or when
    # key material/signing operations fail.
    def self.jwt(config : VapidConfig, audience : String, *, expires_at : Time = Time.utc + DEFAULT_EXPIRATION, now : Time = Time.utc) : String
      signing_input = "#{base64url_encode(jwt_header_json)}.#{base64url_encode(jwt_claims_json(validate_audience(audience), validate_expiration(expires_at, now), config.subject))}"
      "#{signing_input}.#{base64url_encode(sign_es256(signing_input, config.private_key, config.public_key))}"
    end

    # Builds `Authorization` and `Crypto-Key` headers for a push endpoint.
    #
    # Raises `ValidationError` when endpoint parsing, expiration, or signing
    # fails.
    def self.auth_headers(config : VapidConfig, endpoint : String, *, expires_at : Time = Time.utc + DEFAULT_EXPIRATION, now : Time = Time.utc) : AuthHeaders
      token = jwt(config, audience_from_endpoint(endpoint), expires_at: expires_at, now: now)
      AuthHeaders.new(
        authorization: "vapid t=#{token}, k=#{config.public_key}",
        crypto_key: "p256ecdsa=#{config.public_key}"
      )
    end

    # Returns the Web Push audience origin (`scheme://host[:port]`) from endpoint.
    #
    # Raises `ValidationError` when endpoint is not a valid absolute URI.
    def self.audience_from_endpoint(endpoint : String) : String
      uri = URI.parse(endpoint)
      raise ValidationError.new("VAPID endpoint must include scheme and host") unless uri.scheme && uri.host

      String.build do |io|
        io << uri.scheme.not_nil!.downcase << "://" << uri.host.not_nil!
        io << ":#{uri.port}" if uri.port && !default_port?(uri.scheme.not_nil!, uri.port.not_nil!)
      end
    rescue ex : URI::Error
      raise ValidationError.new("VAPID endpoint is invalid: #{ex.message}")
    end

    def self.valid_signature?(token : String, public_key : String) : Bool
      signing_input, signature = extract_signing_input_and_signature(token)
      verify_es256(signing_input, signature, decode_public_key(public_key))
    rescue ValidationError
      false
    end

    private def self.validate_audience(audience : String) : String
      raise ValidationError.new("VAPID audience is required") if audience.strip.empty?
      uri = URI.parse(audience)
      raise ValidationError.new("VAPID audience must include scheme and host") unless uri.scheme && uri.host
      audience
    rescue ex : URI::Error
      raise ValidationError.new("VAPID audience is invalid: #{ex.message}")
    end

    private def self.validate_expiration(expires_at : Time, now : Time) : Int64
      raise ValidationError.new("VAPID expiration must be in the future") unless expires_at > now
      raise ValidationError.new("VAPID expiration must be within 24 hours from now") if expires_at > now + MAX_EXPIRATION
      expires_at.to_unix
    end

    private def self.jwt_header_json : String
      %({"alg":"ES256","typ":"JWT"})
    end

    private def self.jwt_claims_json(audience : String, expiration : Int64, subject : String) : String
      JSON.build do |json|
        json.object do
          json.field "aud", audience
          json.field "exp", expiration
          json.field "sub", subject
        end
      end
    end

    private def self.base64url_encode(value) : String
      Base64.urlsafe_encode(value, false)
    end

    private def self.decode_base64url(field : String, value : String) : Bytes
      raise ValidationError.new("VAPID #{field} must be base64url encoded") unless BASE64URL_PATTERN.matches?(value)
      Base64.decode(value)
    rescue ex : Base64::Error
      raise ValidationError.new("VAPID #{field} must be base64url encoded: #{ex.message}")
    end

    private def self.decode_private_key(private_key : String) : Bytes
      decoded = decode_base64url("private_key", private_key)
      raise ValidationError.new("VAPID private_key must decode to 32 bytes") unless decoded.size == 32
      decoded
    end

    private def self.decode_public_key(public_key : String) : Bytes
      decoded = decode_base64url("public_key", public_key)
      raise ValidationError.new("VAPID public_key must decode to 65 bytes") unless decoded.size == 65
      raise ValidationError.new("VAPID public_key must be an uncompressed P-256 key") unless decoded[0] == 0x04
      decoded
    end

    private def self.default_port?(scheme : String, port : Int32) : Bool
      (scheme.downcase == "https" && port == 443) || (scheme.downcase == "http" && port == 80)
    end

    private def self.sign_es256(signing_input : String, private_key : String, public_key : String) : Bytes
      key = Pointer(Void).null.as(LibCrypto::EC_KEY)
      signature = Pointer(Void).null.as(LibCrypto::ECDSA_SIG)
      key = build_signing_key(decode_public_key(public_key), decode_private_key(private_key))
      signature = LibCrypto.ecdsa_do_sign(Digest::SHA256.digest(signing_input).to_unsafe, 32, key)
      raise ValidationError.new("Failed to sign VAPID JWT") if signature.null?
      signature_to_raw(signature)
    ensure
      LibCrypto.ecdsa_sig_free(signature) if signature && !signature.null?
      LibCrypto.ec_key_free(key) if key && !key.null?
    end

    private def self.verify_es256(signing_input : String, signature : Bytes, public_key : Bytes) : Bool
      key = Pointer(Void).null.as(LibCrypto::EC_KEY)
      ecdsa_signature = Pointer(Void).null.as(LibCrypto::ECDSA_SIG)
      key = build_verification_key(public_key)
      ecdsa_signature = raw_to_ecdsa_signature(signature)
      LibCrypto.ecdsa_do_verify(Digest::SHA256.digest(signing_input).to_unsafe, 32, ecdsa_signature, key) == 1
    ensure
      LibCrypto.ecdsa_sig_free(ecdsa_signature) if ecdsa_signature && !ecdsa_signature.null?
      LibCrypto.ec_key_free(key) if key && !key.null?
    end

    private def self.extract_signing_input_and_signature(token : String) : Tuple(String, Bytes)
      parts = token.split(".")
      raise ValidationError.new("JWT must contain exactly three segments") unless parts.size == 3
      {"#{parts[0]}.#{parts[1]}", decode_base64url("signature", parts[2])}
    end

    private def self.signature_to_raw(signature : LibCrypto::ECDSA_SIG) : Bytes
      r = Pointer(Void).null.as(LibCrypto::BIGNUM)
      s = Pointer(Void).null.as(LibCrypto::BIGNUM)
      LibCrypto.ecdsa_sig_get0(signature, pointerof(r), pointerof(s))
      raise ValidationError.new("Failed to extract ECDSA signature values") if r.null? || s.null?

      # JWT ES256 needs fixed-width raw (r || s), not ASN.1 DER.
      raw = Bytes.new(ES256_SIGNATURE_LEN)
      raise ValidationError.new("Failed to serialize ECDSA signature") unless LibCrypto.bn_bn2binpad(r, raw.to_unsafe, 32) == 32
      raise ValidationError.new("Failed to serialize ECDSA signature") unless LibCrypto.bn_bn2binpad(s, raw.to_unsafe + 32, 32) == 32
      raw
    end

    private def self.raw_to_ecdsa_signature(raw_signature : Bytes) : LibCrypto::ECDSA_SIG
      raise ValidationError.new("VAPID signature must decode to 64 bytes") unless raw_signature.size == ES256_SIGNATURE_LEN

      signature = LibCrypto.ecdsa_sig_new
      raise ValidationError.new("Failed to allocate ECDSA signature") if signature.null?

      r = LibCrypto.bn_bin2bn(raw_signature.to_unsafe, 32, Pointer(Void).null.as(LibCrypto::BIGNUM))
      s = LibCrypto.bn_bin2bn(raw_signature.to_unsafe + 32, 32, Pointer(Void).null.as(LibCrypto::BIGNUM))
      if r.null? || s.null?
        LibCrypto.bn_free(r) unless r.null?
        LibCrypto.bn_free(s) unless s.null?
        LibCrypto.ecdsa_sig_free(signature)
        raise ValidationError.new("Failed to parse ECDSA signature values")
      end

      # Ownership of r/s moves to signature on success.
      if LibCrypto.ecdsa_sig_set0(signature, r, s) != 1
        LibCrypto.bn_free(r)
        LibCrypto.bn_free(s)
        LibCrypto.ecdsa_sig_free(signature)
        raise ValidationError.new("Failed to construct ECDSA signature")
      end

      signature
    end

    private def self.build_signing_key(public_key : Bytes, private_key : Bytes) : LibCrypto::EC_KEY
      build_ec_key(public_key, private_key)
    end

    private def self.build_verification_key(public_key : Bytes) : LibCrypto::EC_KEY
      build_ec_key(public_key)
    end

    private def self.build_ec_key(public_key : Bytes, private_key : Bytes? = nil) : LibCrypto::EC_KEY
      key = Pointer(Void).null.as(LibCrypto::EC_KEY)
      key = LibCrypto.ec_key_new_by_curve_name(LibCrypto::NID_X9_62_prime256v1)
      raise ValidationError.new("Failed to initialize P-256 key") if key.null?

      private_bn = Pointer(Void).null.as(LibCrypto::BIGNUM)
      public_point = Pointer(Void).null.as(LibCrypto::EC_POINT)
      key_initialized = false

      private_bn = LibCrypto.bn_bin2bn(private_key.not_nil!.to_unsafe, private_key.not_nil!.size, Pointer(Void).null.as(LibCrypto::BIGNUM)) if private_key
      raise ValidationError.new("Failed to parse VAPID private key") if private_key && private_bn.null?
      raise ValidationError.new("Failed to set VAPID private key") if private_key && LibCrypto.ec_key_set_private_key(key, private_bn) != 1

      group = LibCrypto.ec_key_get0_group(key)
      raise ValidationError.new("Failed to access P-256 group") if group.null?

      public_point = LibCrypto.ec_point_new(group)
      raise ValidationError.new("Failed to allocate EC point") if public_point.null?
      raise ValidationError.new("Failed to parse VAPID public key") unless LibCrypto.ec_point_oct2point(group, public_point, public_key.to_unsafe, public_key.size, Pointer(Void).null) == 1
      raise ValidationError.new("Failed to set VAPID public key") unless LibCrypto.ec_key_set_public_key(key, public_point) == 1

      raise ValidationError.new("VAPID key material is invalid") unless LibCrypto.ec_key_check_key(key) == 1
      key_initialized = true
      key
    ensure
      LibCrypto.ec_key_free(key) if !key_initialized && key && !key.null?
      LibCrypto.bn_free(private_bn) if private_bn && !private_bn.null?
      LibCrypto.ec_point_free(public_point) if public_point && !public_point.null?
    end
  end
end

lib LibCrypto
  type BIGNUM = Void*
  type EC_GROUP = Void*
  type EC_POINT = Void*
  type ECDSA_SIG = Void*

  fun bn_bin2bn = BN_bin2bn(s : UInt8*, len : Int32, ret : BIGNUM) : BIGNUM
  fun bn_free = BN_free(a : BIGNUM)
  fun bn_bn2binpad = BN_bn2binpad(a : BIGNUM, to : UInt8*, tolen : Int32) : Int32

  fun ec_key_get0_group = EC_KEY_get0_group(key : EC_KEY) : EC_GROUP
  fun ec_key_set_private_key = EC_KEY_set_private_key(key : EC_KEY, prv : BIGNUM) : Int32
  fun ec_key_set_public_key = EC_KEY_set_public_key(key : EC_KEY, pub : EC_POINT) : Int32
  fun ec_key_check_key = EC_KEY_check_key(key : EC_KEY) : Int32

  fun ec_point_new = EC_POINT_new(group : EC_GROUP) : EC_POINT
  fun ec_point_free = EC_POINT_free(point : EC_POINT)
  fun ec_point_oct2point = EC_POINT_oct2point(group : EC_GROUP, point : EC_POINT, buf : UInt8*, len : SizeT, ctx : Void*) : Int32

  fun ecdsa_do_sign = ECDSA_do_sign(dgst : UInt8*, dgst_len : Int32, key : EC_KEY) : ECDSA_SIG
  fun ecdsa_do_verify = ECDSA_do_verify(dgst : UInt8*, dgst_len : Int32, sig : ECDSA_SIG, key : EC_KEY) : Int32
  fun ecdsa_sig_new = ECDSA_SIG_new : ECDSA_SIG
  fun ecdsa_sig_free = ECDSA_SIG_free(sig : ECDSA_SIG)
  fun ecdsa_sig_get0 = ECDSA_SIG_get0(sig : ECDSA_SIG, pr : BIGNUM*, ps : BIGNUM*)
  fun ecdsa_sig_set0 = ECDSA_SIG_set0(sig : ECDSA_SIG, r : BIGNUM, s : BIGNUM) : Int32
end
