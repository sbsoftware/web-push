require "http/headers"

module WebPush
  module RequestBuilder
    def self.push(subscription : Subscription, vapid_config : VapidConfig, ttl : Int32, payload : String, *, expires_at : Time = Time.utc + Vapid::DEFAULT_EXPIRATION, now : Time = Time.utc) : PushRequest
      validate_ttl(ttl)
      vapid_headers = Vapid.auth_headers(vapid_config, subscription.endpoint, expires_at: expires_at, now: now)
      sender_key_pair = generate_sender_key_pair
      build_encrypted_push_request(subscription, vapid_headers, ttl, payload, sender_key_pair[:public_key], sender_key_pair[:private_key], generate_salt)
    end

    private def self.validate_ttl(ttl : Int32)
      raise ValidationError.new("Push request field 'ttl' must be greater than or equal to 0") if ttl < 0
    end
  end
end
