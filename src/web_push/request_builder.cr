require "http/headers"

module WebPush
  module RequestBuilder
    def self.push(subscription : Subscription, vapid_config : VapidConfig, payload : String? = nil, *, ttl : Int32, expires_at : Time = Time.utc + Vapid::DEFAULT_EXPIRATION, now : Time = Time.utc) : PushRequest
      validate_ttl(ttl)
      vapid_headers = Vapid.auth_headers(vapid_config, subscription.endpoint, expires_at: expires_at, now: now)
      return build_no_payload_push_request(subscription, vapid_headers, ttl) if payload.nil? || payload.empty?
      sender_key_pair = generate_sender_key_pair
      build_encrypted_push_request(subscription, vapid_headers, ttl, payload, sender_key_pair[:public_key], sender_key_pair[:private_key], generate_salt)
    end

    private def self.validate_ttl(ttl : Int32)
      raise ValidationError.new("Push request field 'ttl' must be greater than or equal to 0") if ttl < 0
    end

    private def self.build_no_payload_push_request(subscription : Subscription, vapid_headers : Vapid::AuthHeaders, ttl : Int32) : PushRequest
      PushRequest.new(
        endpoint: subscription.endpoint,
        headers: HTTP::Headers{
          "TTL"           => ttl.to_s,
          "Authorization" => vapid_headers.authorization,
          "Crypto-Key"    => vapid_headers.crypto_key,
        }
      )
    end
  end
end
