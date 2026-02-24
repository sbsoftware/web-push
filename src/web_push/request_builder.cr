require "http/headers"

module WebPush
  module RequestBuilder
    def self.no_payload_push(subscription : Subscription, vapid_config : VapidConfig, ttl : Int32, *, expires_at : Time = Time.utc + Vapid::DEFAULT_EXPIRATION, now : Time = Time.utc) : PushRequest
      validate_ttl(ttl)
      vapid_headers = Vapid.auth_headers(vapid_config, subscription.endpoint, expires_at: expires_at, now: now)

      PushRequest.new(
        endpoint: subscription.endpoint,
        headers: HTTP::Headers{
          "TTL"           => ttl.to_s,
          "Authorization" => vapid_headers.authorization,
          "Crypto-Key"    => vapid_headers.crypto_key,
        }
      )
    end

    private def self.validate_ttl(ttl : Int32)
      raise ValidationError.new("Push request field 'ttl' must be greater than or equal to 0") if ttl < 0
    end
  end
end
