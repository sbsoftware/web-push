require "json"

module WebPush
  # Browser subscription data required for Web Push encryption and delivery.
  #
  # `endpoint`, `p256dh`, and `auth` are all required and must be non-empty.
  struct Subscription
    getter endpoint : String
    getter p256dh : String
    getter auth : String

    # Creates a subscription from already extracted fields.
    #
    # Raises `ValidationError` when any required field is missing or blank.
    def initialize(@endpoint : String, @p256dh : String, @auth : String)
      validate_required_field("endpoint", @endpoint)
      validate_required_field("p256dh", @p256dh)
      validate_required_field("auth", @auth)
    end

    # Parses a subscription from JSON input.
    #
    # Accepted shapes:
    # - Flattened keys: `{"endpoint":"...","p256dh":"...","auth":"..."}`
    # - Nested keys: `{"endpoint":"...","keys":{"p256dh":"...","auth":"..."}}`
    #
    # Raises `ValidationError` for parse failures, missing fields, or invalid types.
    def self.from_json(input : String) : self
      from_json(JSON.parse(input))
    rescue ex : JSON::ParseException
      raise ValidationError.new("Invalid subscription JSON: #{ex.message}")
    end

    # Parses a subscription from a pre-parsed JSON object.
    #
    # Raises `ValidationError` when JSON is not an object, required fields are
    # missing, fields are not strings, or values are blank.
    def self.from_json(value : JSON::Any) : self
      object = value.as_h?
      raise ValidationError.new("Subscription JSON must be an object") unless object

      endpoint = extract_required_string(object, "endpoint")

      # Accept either flattened keys (`p256dh`, `auth`) or `keys` object.
      keys = object["keys"]?.try(&.as_h?)
      p256dh = extract_key_string(object, keys, "p256dh")
      auth = extract_key_string(object, keys, "auth")

      new(endpoint, p256dh, auth)
    end

    # Parses a subscription from a Hash with string keys.
    #
    # Required keys are `endpoint`, `p256dh`, and `auth`.
    # Raises `ValidationError` when values are missing or blank.
    def self.from_hash(hash : Hash(String, String?)) : self
      endpoint = extract_required_string(hash, "endpoint")
      p256dh = extract_required_string(hash, "p256dh")
      auth = extract_required_string(hash, "auth")

      new(endpoint, p256dh, auth)
    end

    def to_h : Hash(String, String)
      {
        "endpoint" => endpoint,
        "p256dh"   => p256dh,
        "auth"     => auth,
      }
    end

    def to_json(json : JSON::Builder)
      json.object do
        json.field "endpoint", endpoint
        json.field "p256dh", p256dh
        json.field "auth", auth
      end
    end

    private def self.extract_key_string(object : Hash(String, JSON::Any), keys : Hash(String, JSON::Any)?, field : String) : String
      value = object[field]? || keys.try(&.[field]?)
      raise ValidationError.new("Subscription field '#{field}' is required") unless value
      extract_string(value, field)
    end

    private def self.extract_required_string(object : Hash(String, JSON::Any), field : String) : String
      value = object[field]?
      raise ValidationError.new("Subscription field '#{field}' is required") unless value
      extract_string(value, field)
    end

    private def self.extract_required_string(object : Hash(String, String?), field : String) : String
      value = object[field]?
      raise ValidationError.new("Subscription field '#{field}' is required") unless value
      validate_required_field(field, value)
      value
    end

    private def self.extract_string(value : JSON::Any, field : String) : String
      string = value.as_s?
      raise ValidationError.new("Subscription field '#{field}' must be a string") unless string
      validate_required_field(field, string)
      string
    end

    private def self.validate_required_field(field : String, value : String)
      raise ValidationError.new("Subscription field '#{field}' is required") if value.strip.empty?
    end

    private def validate_required_field(field : String, value : String)
      raise ValidationError.new("Subscription field '#{field}' is required") if value.strip.empty?
    end
  end
end
