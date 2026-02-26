require "../spec_helper"

private INTEGRATION_VAPID_PUBLIC_KEY    = "BNpReHjFgbvl8tsrMoRJl-eKTIhYQXUsVPgIMGB2AUUG-ufq4N6F4FRsBiphNVCrkXGB5EPExzQoa6Qzng0yxyU"
private INTEGRATION_VAPID_PRIVATE_KEY   = "79Om5Okowk6Tkd-1moexy7bIXuQQb5o2J9SWPq75Wnw"
private INTEGRATION_VAPID_SUBJECT       = "mailto:admin@example.com"
private INTEGRATION_SENDER_PRIVATE_KEY  = "ftg1YXCeMJaKIdTY60kacOm17bE-4xap6oDaoZS9yUY"
private INTEGRATION_SENDER_PUBLIC_KEY   = "BPnQy9XtZAidK7wBHxDSlh_REH_TuIokjxKDH7e5SCF3JZAEv1G2tkp9QhQ86i1QfhJbgg-Hgoxg07v9BANBfb8"
private INTEGRATION_RECEIVER_PUBLIC_KEY = "BNnjgxL7iRJVGG2WfKoCcEas8uXFYFw4b6ivLqWsMp8pMhmdN3LRYQTyFWuE_MOCSD_OLdj2K2gtH3ggUe4nYeY"
private INTEGRATION_AUTH_SECRET         = "KsWb025fekARlsIkDa5Vnw"
private INTEGRATION_SALT                = "dxOqCUxLOY6x9yBbYuyaMw"
private INTEGRATION_PAYLOAD             = %({"title":"Hello"})
private INTEGRATION_CEK                 = "skRc4aaecTk6Q8_gpVuHZA"
private INTEGRATION_NONCE               = "88LWyqTXpzTxOZn5"
private INTEGRATION_FRAMED_BODY_HEX     = "7713aa094c4b398eb1f7205b62ec9a33000010004104f9d0cbd5ed64089d2bbc011f10d2961fd1107fd3b88a248f12831fb7b9482177259004bf51b6b64a7d42143cea2d507e125b820f87828c60d3bbfd0403417dbfb384d2ede8cea414533f844d005aaf5724acc56e7ff3fad1b97ad9a0a711d448b339"

module WebPush
  module RequestBuilder
    def self.spec_push_with_encryption_material(subscription : Subscription, vapid_config : VapidConfig, ttl : Int32, payload : String, sender_public_key : String, sender_private_key : String, salt : String, *, expires_at : Time = Time.utc + Vapid::DEFAULT_EXPIRATION, now : Time = Time.utc) : PushRequest
      validate_ttl(ttl)
      build_encrypted_push_request(subscription, Vapid.auth_headers(vapid_config, subscription.endpoint, expires_at: expires_at, now: now), ttl, payload, sender_public_key, sender_private_key, salt)
    end

    def self.spec_derive_payload_key_material(subscription : Subscription, sender_public_key : String, sender_private_key : String, salt : String) : NamedTuple(content_encryption_key: Bytes, nonce: Bytes)
      material = derive_key_schedule(subscription, sender_public_key, sender_private_key, salt)
      {content_encryption_key: material.content_encryption_key, nonce: material.nonce}
    end
  end
end

describe WebPush::RequestBuilder do
  describe "payload encryption integration vectors" do
    it "keeps key schedule, encrypted body, and metadata coherent" do
      now = Time.unix(1_710_000_000)
      request = WebPush::RequestBuilder.spec_push_with_encryption_material(
        WebPush::Subscription.new(endpoint: "https://push.example/send/123", p256dh: INTEGRATION_RECEIVER_PUBLIC_KEY, auth: INTEGRATION_AUTH_SECRET),
        WebPush::VapidConfig.new(public_key: INTEGRATION_VAPID_PUBLIC_KEY, private_key: INTEGRATION_VAPID_PRIVATE_KEY, subject: INTEGRATION_VAPID_SUBJECT),
        120,
        INTEGRATION_PAYLOAD,
        INTEGRATION_SENDER_PUBLIC_KEY,
        INTEGRATION_SENDER_PRIVATE_KEY,
        INTEGRATION_SALT,
        expires_at: now + 1.hour,
        now: now
      )
      material = WebPush::RequestBuilder.spec_derive_payload_key_material(
        WebPush::Subscription.new(endpoint: "https://push.example/send/123", p256dh: INTEGRATION_RECEIVER_PUBLIC_KEY, auth: INTEGRATION_AUTH_SECRET),
        INTEGRATION_SENDER_PUBLIC_KEY,
        INTEGRATION_SENDER_PRIVATE_KEY,
        INTEGRATION_SALT
      )

      Base64.urlsafe_encode(material[:content_encryption_key], false).should eq(INTEGRATION_CEK)
      Base64.urlsafe_encode(material[:nonce], false).should eq(INTEGRATION_NONCE)
      request.body.to_slice.hexstring.should eq(INTEGRATION_FRAMED_BODY_HEX)
      request.headers["TTL"].should eq("120")
      request.headers["Content-Encoding"].should eq("aes128gcm")
      request.headers["Crypto-Key"].should eq("dh=#{INTEGRATION_SENDER_PUBLIC_KEY};p256ecdsa=#{INTEGRATION_VAPID_PUBLIC_KEY}")
      request.body.to_slice[0, 16].should eq(Base64.decode(INTEGRATION_SALT))
      IO::Memory.new(request.body.to_slice[16, 4]).read_bytes(UInt32, IO::ByteFormat::BigEndian).should eq(4096_u32)
      request.body.to_slice[20].should eq(65_u8)
      Base64.urlsafe_encode(request.body.to_slice[21, request.body.to_slice[20]], false).should eq(INTEGRATION_SENDER_PUBLIC_KEY)
    end

    it "raises explicit errors for malformed and missing encryption key material" do
      subscription = WebPush::Subscription.new(endpoint: "https://push.example/send/123", p256dh: INTEGRATION_RECEIVER_PUBLIC_KEY, auth: INTEGRATION_AUTH_SECRET)
      vapid_config = WebPush::VapidConfig.new(public_key: INTEGRATION_VAPID_PUBLIC_KEY, private_key: INTEGRATION_VAPID_PRIVATE_KEY, subject: INTEGRATION_VAPID_SUBJECT)

      expect_raises(WebPush::ValidationError, "Push encryption field 'sender_public_key' must be base64url encoded") do
        WebPush::RequestBuilder.spec_push_with_encryption_material(subscription, vapid_config, 120, INTEGRATION_PAYLOAD, "not+urlsafe", INTEGRATION_SENDER_PRIVATE_KEY, INTEGRATION_SALT)
      end

      expect_raises(WebPush::ValidationError, "Push encryption field 'sender_private_key' must be base64url encoded") do
        WebPush::RequestBuilder.spec_push_with_encryption_material(subscription, vapid_config, 120, INTEGRATION_PAYLOAD, INTEGRATION_SENDER_PUBLIC_KEY, "", INTEGRATION_SALT)
      end

      expect_raises(WebPush::ValidationError, "Push encryption field 'subscription.auth' must decode to 16 bytes") do
        WebPush::RequestBuilder.spec_push_with_encryption_material(
          WebPush::Subscription.new(endpoint: "https://push.example/send/123", p256dh: INTEGRATION_RECEIVER_PUBLIC_KEY, auth: "AQI"),
          vapid_config,
          120,
          INTEGRATION_PAYLOAD,
          INTEGRATION_SENDER_PUBLIC_KEY,
          INTEGRATION_SENDER_PRIVATE_KEY,
          INTEGRATION_SALT
        )
      end
    end
  end
end
