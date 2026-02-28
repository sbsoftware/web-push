require "json"

module WebPush
  # Validated message payload and TTL metadata.
  #
  # `payload` must be non-empty and `ttl` must be `>= 0`.
  struct Message
    getter payload : String
    getter ttl : Int32

    # Creates a message from direct values.
    #
    # Raises `ValidationError` if `payload` is blank or `ttl` is negative.
    def initialize(@payload : String, @ttl : Int32)
      validate_payload(payload)
      validate_ttl(ttl)
    end

    # Parses a message from JSON text.
    #
    # Raises `ValidationError` for parse failures, missing fields, invalid types,
    # blank payloads, or negative TTL values.
    def self.from_json(input : String) : self
      from_json(JSON.parse(input))
    rescue ex : JSON::ParseException
      raise ValidationError.new("Invalid message JSON: #{ex.message}")
    end

    # Parses a message from pre-parsed JSON data.
    #
    # Raises `ValidationError` when JSON is not an object, required fields are
    # missing, fields are invalid, or values fail validation.
    def self.from_json(value : JSON::Any) : self
      object = value.as_h?
      raise ValidationError.new("Message JSON must be an object") unless object

      payload = extract_required_string(object, "payload")
      ttl = extract_required_int(object, "ttl")

      new(payload, ttl)
    end

    def to_h : Hash(String, String | Int32)
      {
        "payload" => payload,
        "ttl"     => ttl,
      }
    end

    def to_json(json : JSON::Builder)
      json.object do
        json.field "payload", payload
        json.field "ttl", ttl
      end
    end

    private def self.extract_required_string(object : Hash(String, JSON::Any), field : String) : String
      value = object[field]?
      raise ValidationError.new("Message field '#{field}' is required") unless value

      string = value.as_s?
      raise ValidationError.new("Message field '#{field}' must be a string") unless string

      validate_payload(string)
      string
    end

    private def self.extract_required_int(object : Hash(String, JSON::Any), field : String) : Int32
      value = object[field]?
      raise ValidationError.new("Message field '#{field}' is required") unless value

      int = value.as_i?
      raise ValidationError.new("Message field '#{field}' must be an integer") unless int

      validate_ttl(int)
      int
    end

    private def self.validate_payload(payload : String)
      raise ValidationError.new("Message field 'payload' is required") if payload.strip.empty?
    end

    private def self.validate_ttl(ttl : Int32)
      raise ValidationError.new("Message field 'ttl' must be greater than or equal to 0") if ttl < 0
    end

    private def validate_payload(payload : String)
      raise ValidationError.new("Message field 'payload' is required") if payload.strip.empty?
    end

    private def validate_ttl(ttl : Int32)
      raise ValidationError.new("Message field 'ttl' must be greater than or equal to 0") if ttl < 0
    end
  end
end
