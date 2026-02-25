require "../spec_helper"

private KEY_SCHEDULE_SENDER_PRIVATE_KEY   = "ftg1YXCeMJaKIdTY60kacOm17bE-4xap6oDaoZS9yUY"
private KEY_SCHEDULE_SENDER_PUBLIC_KEY    = "BPnQy9XtZAidK7wBHxDSlh_REH_TuIokjxKDH7e5SCF3JZAEv1G2tkp9QhQ86i1QfhJbgg-Hgoxg07v9BANBfb8"
private KEY_SCHEDULE_RECEIVER_PRIVATE_KEY = "vM7gtiCy8xi-HVfg3OlfdaRQC_DvJVRSNzL0owI4e5w"
private KEY_SCHEDULE_RECEIVER_PUBLIC_KEY  = "BNnjgxL7iRJVGG2WfKoCcEas8uXFYFw4b6ivLqWsMp8pMhmdN3LRYQTyFWuE_MOCSD_OLdj2K2gtH3ggUe4nYeY"
private KEY_SCHEDULE_AUTH_SECRET          = "KsWb025fekARlsIkDa5Vnw"
private KEY_SCHEDULE_SALT                 = "dxOqCUxLOY6x9yBbYuyaMw"
private KEY_SCHEDULE_SHARED_SECRET        = "r7OTtt8054hDQ6MU1MORqmgC_bSMe_st8z4Sc7Xlqw0"
private KEY_SCHEDULE_CEK                  = "skRc4aaecTk6Q8_gpVuHZA"
private KEY_SCHEDULE_NONCE                = "88LWyqTXpzTxOZn5"

private def bytes_from_hex(hex : String) : Bytes
  raise "hex input must have an even number of chars" unless hex.size.even?
  Bytes.new(hex.size // 2) { |index| hex[index * 2, 2].to_u8(16) }
end

module WebPush
  module RequestBuilder
    def self.spec_derive_key_schedule(subscription : Subscription, sender_public_key : String, sender_private_key : String, salt : String) : NamedTuple(content_encryption_key: Bytes, nonce: Bytes)
      material = derive_key_schedule(subscription, sender_public_key, sender_private_key, salt)
      {content_encryption_key: material.content_encryption_key, nonce: material.nonce}
    end

    def self.spec_ecdh_shared_secret(sender_private_key : String, sender_public_key : String, receiver_public_key : String) : Bytes
      ecdh_shared_secret(decode_fixed_length_key("sender_private_key", sender_private_key, P256_PRIVATE_KEY_BYTES), decode_p256_public_key("sender_public_key", sender_public_key), decode_p256_public_key("receiver_public_key", receiver_public_key))
    end

    def self.spec_hkdf_extract(salt : Bytes, input_key_material : Bytes) : Bytes
      hkdf_extract(salt, input_key_material)
    end

    def self.spec_hkdf_expand(prk : Bytes, info : Bytes, output_size : Int32) : Bytes
      hkdf_expand(prk, info, output_size)
    end
  end
end

describe WebPush::RequestBuilder do
  describe "private key-schedule primitives" do
    it "matches the RFC5869 SHA-256 HKDF vector" do
      prk = WebPush::RequestBuilder.spec_hkdf_extract(
        bytes_from_hex("000102030405060708090a0b0c"),
        Bytes.new(22, 0x0b_u8)
      )
      okm = WebPush::RequestBuilder.spec_hkdf_expand(
        prk,
        bytes_from_hex("f0f1f2f3f4f5f6f7f8f9"),
        42
      )

      prk.hexstring.should eq("077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5")
      okm.hexstring.should eq("3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865")
    end

    it "derives the expected ECDH shared secret from known P-256 keys" do
      secret_from_sender = WebPush::RequestBuilder.spec_ecdh_shared_secret(
        KEY_SCHEDULE_SENDER_PRIVATE_KEY,
        KEY_SCHEDULE_SENDER_PUBLIC_KEY,
        KEY_SCHEDULE_RECEIVER_PUBLIC_KEY
      )
      secret_from_receiver = WebPush::RequestBuilder.spec_ecdh_shared_secret(
        KEY_SCHEDULE_RECEIVER_PRIVATE_KEY,
        KEY_SCHEDULE_RECEIVER_PUBLIC_KEY,
        KEY_SCHEDULE_SENDER_PUBLIC_KEY
      )

      Base64.urlsafe_encode(secret_from_sender, false).should eq(KEY_SCHEDULE_SHARED_SECRET)
      secret_from_sender.should eq(secret_from_receiver)
    end

    it "derives deterministic CEK and nonce material" do
      material = WebPush::RequestBuilder.spec_derive_key_schedule(
        WebPush::Subscription.new(endpoint: "https://push.example/send/123", p256dh: KEY_SCHEDULE_RECEIVER_PUBLIC_KEY, auth: KEY_SCHEDULE_AUTH_SECRET),
        KEY_SCHEDULE_SENDER_PUBLIC_KEY,
        KEY_SCHEDULE_SENDER_PRIVATE_KEY,
        KEY_SCHEDULE_SALT
      )

      Base64.urlsafe_encode(material[:content_encryption_key], false).should eq(KEY_SCHEDULE_CEK)
      Base64.urlsafe_encode(material[:nonce], false).should eq(KEY_SCHEDULE_NONCE)
    end

    it "raises explicit errors for invalid key material" do
      expect_raises(WebPush::ValidationError, "Push encryption field 'subscription.p256dh' must be base64url encoded") do
        WebPush::RequestBuilder.spec_derive_key_schedule(
          WebPush::Subscription.new(endpoint: "https://push.example/send/123", p256dh: "not+urlsafe", auth: KEY_SCHEDULE_AUTH_SECRET),
          KEY_SCHEDULE_SENDER_PUBLIC_KEY,
          KEY_SCHEDULE_SENDER_PRIVATE_KEY,
          KEY_SCHEDULE_SALT
        )
      end

      expect_raises(WebPush::ValidationError, "Push encryption field 'subscription.auth' must decode to 16 bytes") do
        WebPush::RequestBuilder.spec_derive_key_schedule(
          WebPush::Subscription.new(endpoint: "https://push.example/send/123", p256dh: KEY_SCHEDULE_RECEIVER_PUBLIC_KEY, auth: "AQI"),
          KEY_SCHEDULE_SENDER_PUBLIC_KEY,
          KEY_SCHEDULE_SENDER_PRIVATE_KEY,
          KEY_SCHEDULE_SALT
        )
      end

      expect_raises(WebPush::ValidationError, "Push encryption sender key material is invalid") do
        WebPush::RequestBuilder.spec_derive_key_schedule(
          WebPush::Subscription.new(endpoint: "https://push.example/send/123", p256dh: KEY_SCHEDULE_RECEIVER_PUBLIC_KEY, auth: KEY_SCHEDULE_AUTH_SECRET),
          KEY_SCHEDULE_RECEIVER_PUBLIC_KEY,
          KEY_SCHEDULE_SENDER_PRIVATE_KEY,
          KEY_SCHEDULE_SALT
        )
      end
    end
  end
end
