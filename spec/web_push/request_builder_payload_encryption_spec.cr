require "../spec_helper"

private ENCRYPTION_SENDER_PRIVATE_KEY   = "ftg1YXCeMJaKIdTY60kacOm17bE-4xap6oDaoZS9yUY"
private ENCRYPTION_SENDER_PUBLIC_KEY    = "BPnQy9XtZAidK7wBHxDSlh_REH_TuIokjxKDH7e5SCF3JZAEv1G2tkp9QhQ86i1QfhJbgg-Hgoxg07v9BANBfb8"
private ENCRYPTION_RECEIVER_PUBLIC_KEY  = "BNnjgxL7iRJVGG2WfKoCcEas8uXFYFw4b6ivLqWsMp8pMhmdN3LRYQTyFWuE_MOCSD_OLdj2K2gtH3ggUe4nYeY"
private ENCRYPTION_AUTH_SECRET          = "KsWb025fekARlsIkDa5Vnw"
private ENCRYPTION_SALT                 = "dxOqCUxLOY6x9yBbYuyaMw"
private ENCRYPTION_CEK                  = "skRc4aaecTk6Q8_gpVuHZA"
private ENCRYPTION_NONCE                = "88LWyqTXpzTxOZn5"
private ENCRYPTION_PAYLOAD              = %({"title":"Hello"})
private ENCRYPTION_RECORD_HEX           = "b384d2ede8cea414533f844d005aaf5724acc56e7ff3fad1b97ad9a0a711d448b339"
private ENCRYPTION_FRAMED_BODY_HEX      = "7713aa094c4b398eb1f7205b62ec9a33000010004104f9d0cbd5ed64089d2bbc011f10d2961fd1107fd3b88a248f12831fb7b9482177259004bf51b6b64a7d42143cea2d507e125b820f87828c60d3bbfd0403417dbfb384d2ede8cea414533f844d005aaf5724acc56e7ff3fad1b97ad9a0a711d448b339"
private ENCRYPTION_FRAMED_BODY_RS24_HEX = "7713aa094c4b398eb1f7205b62ec9a33000000184104f9d0cbd5ed64089d2bbc011f10d2961fd1107fd3b88a248f12831fb7b9482177259004bf51b6b64a7d42143cea2d507e125b820f87828c60d3bbfd0403417dbfb384d2ede8cea43739e7ba87149ee9b83f7c5b56962420e6b7757d0357bc1d6f3db34073d1811c89c632672fa482f9b361e9975ac640feae5da7593a128cfa231c7dfdc0"

private def final_record_plaintext(payload : String) : Bytes
  record = IO::Memory.new(payload.bytesize + 1)
  record.write(payload.to_slice)
  record.write_byte(0x02_u8)
  record.to_slice
end

module WebPush
  module RequestBuilder
    def self.spec_encrypt_payload_body(subscription : Subscription, payload : String, sender_public_key : String, sender_private_key : String, salt : String, record_size : Int32 = DEFAULT_RECORD_SIZE) : Bytes
      encrypt_payload_body(subscription, payload, sender_public_key, sender_private_key, salt, record_size)
    end

    def self.spec_aes128gcm_encrypt(plaintext : Bytes, content_encryption_key : Bytes, nonce : Bytes) : Bytes
      aes128gcm_encrypt(plaintext, content_encryption_key, nonce)
    end

    def self.spec_record_nonce(base_nonce : Bytes, sequence_number : UInt64) : Bytes
      record_nonce(base_nonce, sequence_number)
    end
  end
end

describe WebPush::RequestBuilder do
  describe "private payload encryption primitives" do
    it "encrypts a single record with deterministic AES-128-GCM output" do
      WebPush::RequestBuilder.spec_aes128gcm_encrypt(
        final_record_plaintext(ENCRYPTION_PAYLOAD),
        Base64.decode(ENCRYPTION_CEK),
        Base64.decode(ENCRYPTION_NONCE)
      ).hexstring.should eq(ENCRYPTION_RECORD_HEX)
    end

    it "frames an encrypted payload body with deterministic output" do
      WebPush::RequestBuilder.spec_encrypt_payload_body(
        WebPush::Subscription.new(endpoint: "https://push.example/send/123", p256dh: ENCRYPTION_RECEIVER_PUBLIC_KEY, auth: ENCRYPTION_AUTH_SECRET),
        ENCRYPTION_PAYLOAD,
        ENCRYPTION_SENDER_PUBLIC_KEY,
        ENCRYPTION_SENDER_PRIVATE_KEY,
        ENCRYPTION_SALT
      ).hexstring.should eq(ENCRYPTION_FRAMED_BODY_HEX)
    end

    it "splits payloads into multiple records when record size is small" do
      WebPush::RequestBuilder.spec_encrypt_payload_body(
        WebPush::Subscription.new(endpoint: "https://push.example/send/123", p256dh: ENCRYPTION_RECEIVER_PUBLIC_KEY, auth: ENCRYPTION_AUTH_SECRET),
        ENCRYPTION_PAYLOAD,
        ENCRYPTION_SENDER_PUBLIC_KEY,
        ENCRYPTION_SENDER_PRIVATE_KEY,
        ENCRYPTION_SALT,
        24
      ).hexstring.should eq(ENCRYPTION_FRAMED_BODY_RS24_HEX)
    end

    it "derives record nonces by XORing sequence numbers into the base nonce" do
      base_nonce = Base64.decode(ENCRYPTION_NONCE)
      WebPush::RequestBuilder.spec_record_nonce(base_nonce, 0_u64).hexstring.should eq("f3c2d6caa4d7a734f13999f9")
      WebPush::RequestBuilder.spec_record_nonce(base_nonce, 1_u64).hexstring.should eq("f3c2d6caa4d7a734f13999f8")
      WebPush::RequestBuilder.spec_record_nonce(base_nonce, 2_u64).hexstring.should eq("f3c2d6caa4d7a734f13999fb")
    end

    it "raises explicit errors for invalid payload encryption inputs" do
      expect_raises(WebPush::ValidationError, "Push encryption payload must not be empty") do
        WebPush::RequestBuilder.spec_encrypt_payload_body(
          WebPush::Subscription.new(endpoint: "https://push.example/send/123", p256dh: ENCRYPTION_RECEIVER_PUBLIC_KEY, auth: ENCRYPTION_AUTH_SECRET),
          "",
          ENCRYPTION_SENDER_PUBLIC_KEY,
          ENCRYPTION_SENDER_PRIVATE_KEY,
          ENCRYPTION_SALT
        )
      end

      expect_raises(WebPush::ValidationError, "Push encryption record size must be at least 18 bytes") do
        WebPush::RequestBuilder.spec_encrypt_payload_body(
          WebPush::Subscription.new(endpoint: "https://push.example/send/123", p256dh: ENCRYPTION_RECEIVER_PUBLIC_KEY, auth: ENCRYPTION_AUTH_SECRET),
          ENCRYPTION_PAYLOAD,
          ENCRYPTION_SENDER_PUBLIC_KEY,
          ENCRYPTION_SENDER_PRIVATE_KEY,
          ENCRYPTION_SALT,
          17
        )
      end

      expect_raises(WebPush::ValidationError, "Push encryption content encryption key must be 16 bytes") do
        WebPush::RequestBuilder.spec_aes128gcm_encrypt(Bytes[0x01_u8], Bytes.new(15, 0_u8), Bytes.new(12, 0_u8))
      end

      expect_raises(WebPush::ValidationError, "Push encryption record sequence exceeds 48-bit limit") do
        WebPush::RequestBuilder.spec_record_nonce(Base64.decode(ENCRYPTION_NONCE), 281_474_976_710_656_u64)
      end
    end
  end
end
