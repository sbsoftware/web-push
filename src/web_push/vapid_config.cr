require "base64"

module WebPush
  struct VapidConfig
    getter public_key : String
    getter private_key : String
    getter subject : String

    private BASE64URL_PATTERN = /\A[A-Za-z0-9_-]+={0,2}\z/

    def initialize(@public_key : String, @private_key : String, @subject : String)
      validate_required_field("public_key", @public_key)
      validate_required_field("private_key", @private_key)
      validate_required_field("subject", @subject)
      validate_subject(@subject)
      validate_private_key(@private_key)
      validate_public_key(@public_key)
    end

    private def validate_required_field(field : String, value : String)
      raise ValidationError.new("VAPID field '#{field}' is required") if value.strip.empty?
    end

    private def validate_subject(subject : String)
      raise ValidationError.new("VAPID field 'subject' must start with 'mailto:' or 'https://'") unless subject.starts_with?("mailto:") || subject.starts_with?("https://")
    end

    private def validate_private_key(private_key : String)
      raise ValidationError.new("VAPID field 'private_key' must decode to 32 bytes") unless decode_base64url("private_key", private_key).size == 32
    end

    private def validate_public_key(public_key : String)
      decoded = decode_base64url("public_key", public_key)
      raise ValidationError.new("VAPID field 'public_key' must decode to 65 bytes") unless decoded.size == 65
      raise ValidationError.new("VAPID field 'public_key' must be an uncompressed P-256 key") unless decoded[0] == 0x04
    end

    private def decode_base64url(field : String, value : String) : Bytes
      raise ValidationError.new("VAPID field '#{field}' must be base64url encoded") unless BASE64URL_PATTERN.matches?(value)
      Base64.decode(value)
    rescue ex : Base64::Error
      raise ValidationError.new("VAPID field '#{field}' must be base64url encoded: #{ex.message}")
    end
  end
end
