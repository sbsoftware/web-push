require "../spec_helper"

private TEST_PUBLIC_KEY  = "BNpReHjFgbvl8tsrMoRJl-eKTIhYQXUsVPgIMGB2AUUG-ufq4N6F4FRsBiphNVCrkXGB5EPExzQoa6Qzng0yxyU"
private TEST_PRIVATE_KEY = "79Om5Okowk6Tkd-1moexy7bIXuQQb5o2J9SWPq75Wnw"
private TEST_SUBJECT     = "mailto:admin@example.com"

private def decode_jwt_segment(segment : String) : JSON::Any
  JSON.parse(String.new(Base64.decode(segment)))
end

describe WebPush::VapidConfig do
  describe ".new" do
    it "builds a config for valid key material" do
      config = WebPush::VapidConfig.new(
        public_key: TEST_PUBLIC_KEY,
        private_key: TEST_PRIVATE_KEY,
        subject: TEST_SUBJECT
      )

      config.public_key.should eq(TEST_PUBLIC_KEY)
      config.private_key.should eq(TEST_PRIVATE_KEY)
      config.subject.should eq(TEST_SUBJECT)
    end

    it "rejects invalid base64url key content" do
      expect_raises(WebPush::ValidationError, "VAPID field 'public_key' must be base64url encoded") do
        WebPush::VapidConfig.new(public_key: "not+urlsafe", private_key: TEST_PRIVATE_KEY, subject: TEST_SUBJECT)
      end
    end

    it "rejects invalid key lengths" do
      expect_raises(WebPush::ValidationError, "VAPID field 'private_key' must decode to 32 bytes") do
        WebPush::VapidConfig.new(public_key: TEST_PUBLIC_KEY, private_key: "AQI", subject: TEST_SUBJECT)
      end
    end

    it "rejects an invalid subject format" do
      expect_raises(WebPush::ValidationError, "VAPID field 'subject' must start with 'mailto:' or 'https://'") do
        WebPush::VapidConfig.new(public_key: TEST_PUBLIC_KEY, private_key: TEST_PRIVATE_KEY, subject: "admin@example.com")
      end
    end
  end
end

describe WebPush::Vapid do
  config = WebPush::VapidConfig.new(
    public_key: TEST_PUBLIC_KEY,
    private_key: TEST_PRIVATE_KEY,
    subject: TEST_SUBJECT
  )

  describe ".audience_from_endpoint" do
    it "extracts endpoint origin without default port" do
      WebPush::Vapid.audience_from_endpoint("https://updates.push.services.mozilla.com:443/wpush/v2/token").should eq("https://updates.push.services.mozilla.com")
    end

    it "keeps a non-default port" do
      WebPush::Vapid.audience_from_endpoint("https://push.example:8443/send").should eq("https://push.example:8443")
    end

    it "rejects endpoints missing scheme or host" do
      expect_raises(WebPush::ValidationError, "VAPID endpoint must include scheme and host") do
        WebPush::Vapid.audience_from_endpoint("/relative/path")
      end
    end
  end

  describe ".jwt" do
    it "builds an ES256 JWT with expected claims" do
      now = Time.unix(1_710_000_000)
      token = WebPush::Vapid.jwt(config, "https://push.example", expires_at: now + 30.minutes, now: now)
      parts = token.split(".")

      parts.size.should eq(3)

      header = decode_jwt_segment(parts[0]).as_h
      claims = decode_jwt_segment(parts[1]).as_h

      header["alg"].as_s.should eq("ES256")
      header["typ"].as_s.should eq("JWT")
      claims["aud"].as_s.should eq("https://push.example")
      claims["sub"].as_s.should eq(TEST_SUBJECT)
      claims["exp"].as_i64.should eq((now + 30.minutes).to_unix)
    end

    it "rejects expired expiration times" do
      now = Time.unix(1_710_000_000)
      expect_raises(WebPush::ValidationError, "VAPID expiration must be in the future") do
        WebPush::Vapid.jwt(config, "https://push.example", expires_at: now, now: now)
      end
    end

    it "rejects expirations beyond the maximum window" do
      now = Time.unix(1_710_000_000)
      expect_raises(WebPush::ValidationError, "VAPID expiration must be within 24 hours from now") do
        WebPush::Vapid.jwt(config, "https://push.example", expires_at: now + 24.hours + 1.second, now: now)
      end
    end
  end

  describe ".auth_headers" do
    it "derives audience from endpoint origin and returns header values" do
      now = Time.unix(1_710_000_000)
      headers = WebPush::Vapid.auth_headers(config, "https://push.example:8443/path?query=1", expires_at: now + 1.hour, now: now)
      match = headers.authorization.match(/\Avapid t=([^,]+), k=#{TEST_PUBLIC_KEY}\z/)

      match.should_not be_nil
      headers.crypto_key.should eq("p256ecdsa=#{TEST_PUBLIC_KEY}")

      token = match.not_nil![1]
      claims = decode_jwt_segment(token.split(".")[1]).as_h
      claims["aud"].as_s.should eq("https://push.example:8443")
    end
  end

  describe ".valid_signature?" do
    it "verifies generated JWT signatures" do
      now = Time.unix(1_710_000_000)
      token = WebPush::Vapid.jwt(config, "https://push.example", expires_at: now + 30.minutes, now: now)

      WebPush::Vapid.valid_signature?(token, TEST_PUBLIC_KEY).should be_true
    end

    it "rejects modified signatures and malformed input" do
      now = Time.unix(1_710_000_000)
      token = WebPush::Vapid.jwt(config, "https://push.example", expires_at: now + 30.minutes, now: now)
      parts = token.split(".")
      tampered_signature = parts[2].starts_with?("A") ? "B#{parts[2][1..]}" : "A#{parts[2][1..]}"

      WebPush::Vapid.valid_signature?("#{parts[0]}.#{parts[1]}.#{tampered_signature}", TEST_PUBLIC_KEY).should be_false
      WebPush::Vapid.valid_signature?("bad-token", TEST_PUBLIC_KEY).should be_false
    end
  end
end
