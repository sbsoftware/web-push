require "../spec_helper"

private REQUEST_TEST_PUBLIC_KEY  = "BNpReHjFgbvl8tsrMoRJl-eKTIhYQXUsVPgIMGB2AUUG-ufq4N6F4FRsBiphNVCrkXGB5EPExzQoa6Qzng0yxyU"
private REQUEST_TEST_PRIVATE_KEY = "79Om5Okowk6Tkd-1moexy7bIXuQQb5o2J9SWPq75Wnw"
private REQUEST_TEST_SUBJECT     = "mailto:admin@example.com"
private REQUEST_TEST_P256DH      = "BNnjgxL7iRJVGG2WfKoCcEas8uXFYFw4b6ivLqWsMp8pMhmdN3LRYQTyFWuE_MOCSD_OLdj2K2gtH3ggUe4nYeY"
private REQUEST_TEST_AUTH        = "KsWb025fekARlsIkDa5Vnw"

describe WebPush::RequestBuilder do
  describe ".push" do
    it "builds a no-payload request with TTL and VAPID auth headers" do
      now = Time.unix(1_710_000_000)
      request = WebPush::RequestBuilder.push(
        WebPush::Subscription.new(endpoint: "https://push.example/send/123", p256dh: "p256dh-key", auth: "auth-key"),
        WebPush::VapidConfig.new(public_key: REQUEST_TEST_PUBLIC_KEY, private_key: REQUEST_TEST_PRIVATE_KEY, subject: REQUEST_TEST_SUBJECT),
        30,
        expires_at: now + 1.hour,
        now: now
      )

      request.endpoint.should eq("https://push.example/send/123")
      request.body.should eq("")
      request.headers["TTL"].should eq("30")
      request.headers["Crypto-Key"].should eq("p256ecdsa=#{REQUEST_TEST_PUBLIC_KEY}")

      authorization = request.headers["Authorization"]
      match = authorization.match(/\Avapid t=([^,]+), k=#{REQUEST_TEST_PUBLIC_KEY}\z/)
      match.should_not be_nil

      token = match.not_nil![1]
      claims = JSON.parse(String.new(Base64.decode(token.split(".")[1]))).as_h

      claims["aud"].as_s.should eq("https://push.example")
      claims["sub"].as_s.should eq(REQUEST_TEST_SUBJECT)
    end

    it "builds an encrypted-payload request with Web Push encryption headers" do
      request = WebPush::RequestBuilder.push(
        WebPush::Subscription.new(endpoint: "https://push.example/send/123", p256dh: REQUEST_TEST_P256DH, auth: REQUEST_TEST_AUTH),
        WebPush::VapidConfig.new(public_key: REQUEST_TEST_PUBLIC_KEY, private_key: REQUEST_TEST_PRIVATE_KEY, subject: REQUEST_TEST_SUBJECT),
        30,
        %({"title":"Hello"})
      )

      request.headers["Content-Encoding"].should eq("aes128gcm")
      request.body.bytesize.should be > 0

      sender_key_bytes = request.body.to_slice[21, request.body.to_slice[20]]
      request.headers["Crypto-Key"].should eq("dh=#{Base64.urlsafe_encode(sender_key_bytes, false)};p256ecdsa=#{REQUEST_TEST_PUBLIC_KEY}")
    end

    it "raises for negative ttl values" do
      expect_raises(WebPush::ValidationError, "Push request field 'ttl' must be greater than or equal to 0") do
        WebPush::RequestBuilder.push(
          WebPush::Subscription.new(endpoint: "https://push.example/send/123", p256dh: "p256dh-key", auth: "auth-key"),
          WebPush::VapidConfig.new(public_key: REQUEST_TEST_PUBLIC_KEY, private_key: REQUEST_TEST_PRIVATE_KEY, subject: REQUEST_TEST_SUBJECT),
          -1
        )
      end
    end
  end
end
