require "../spec_helper"

private CLIENT_TEST_PUBLIC_KEY  = "BNpReHjFgbvl8tsrMoRJl-eKTIhYQXUsVPgIMGB2AUUG-ufq4N6F4FRsBiphNVCrkXGB5EPExzQoa6Qzng0yxyU"
private CLIENT_TEST_PRIVATE_KEY = "79Om5Okowk6Tkd-1moexy7bIXuQQb5o2J9SWPq75Wnw"
private CLIENT_TEST_SUBJECT     = "mailto:admin@example.com"
private CLIENT_TEST_P256DH      = "BNnjgxL7iRJVGG2WfKoCcEas8uXFYFw4b6ivLqWsMp8pMhmdN3LRYQTyFWuE_MOCSD_OLdj2K2gtH3ggUe4nYeY"
private CLIENT_TEST_AUTH        = "KsWb025fekARlsIkDa5Vnw"
private CLIENT_TEST_PAYLOAD     = %({"title":"Hello"})

private struct CapturedPushRequest
  getter method : String
  getter endpoint : String
  getter headers : HTTP::Headers
  getter body : String

  def initialize(@method : String, @endpoint : String, @headers : HTTP::Headers, @body : String)
  end
end

private class StubPushEndpoint
  def initialize(@status_code : Int32, @response_body : String = %({"status":"ok"}))
  end

  def response : HTTP::Client::Response
    HTTP::Client::Response.new(@status_code, body: @response_body)
  end
end

private class StubClient < WebPush::Client
  getter request : CapturedPushRequest?

  def initialize(vapid_config : WebPush::VapidConfig, @stub_push_endpoint : StubPushEndpoint)
    super(vapid_config)
  end

  private def send_request(request : WebPush::PushRequest) : HTTP::Client::Response
    @request = CapturedPushRequest.new(method: "POST", endpoint: request.endpoint, headers: request.headers.dup, body: request.body)
    @stub_push_endpoint.response
  end
end

describe WebPush::Client do
  describe "#send" do
    it "sends an encrypted-payload push request and maps 2xx responses as success" do
      now = Time.unix(1_710_000_000)
      endpoint = "http://127.0.0.1:19191/push"
      stub = StubPushEndpoint.new(201)
      client = StubClient.new(
        WebPush::VapidConfig.new(public_key: CLIENT_TEST_PUBLIC_KEY, private_key: CLIENT_TEST_PRIVATE_KEY, subject: CLIENT_TEST_SUBJECT),
        stub
      )
      result = client.send(
        WebPush::Subscription.new(endpoint: endpoint, p256dh: CLIENT_TEST_P256DH, auth: CLIENT_TEST_AUTH),
        45,
        CLIENT_TEST_PAYLOAD,
        expires_at: now + 1.hour,
        now: now
      )
      request = client.request.not_nil!

      request.method.should eq("POST")
      request.endpoint.should eq(endpoint)
      request.body.bytesize.should be > 0
      request.headers["TTL"].should eq("45")
      request.headers["Content-Encoding"].should eq("aes128gcm")

      sender_key_bytes = request.body.to_slice[21, request.body.to_slice[20]]
      request.headers["Crypto-Key"].should eq("dh=#{Base64.urlsafe_encode(sender_key_bytes, false)};p256ecdsa=#{CLIENT_TEST_PUBLIC_KEY}")

      match = request.headers["Authorization"].match(/\Avapid t=([^,]+), k=#{CLIENT_TEST_PUBLIC_KEY}\z/)
      match.should_not be_nil

      claims = JSON.parse(String.new(Base64.decode(match.not_nil![1].split(".")[1]))).as_h
      claims["aud"].as_s.should eq("http://127.0.0.1:19191")

      result.state.should eq(WebPush::Client::SendState::Success)
      result.status_code.should eq(201)
      result.body.should eq(%({"status":"ok"}))
    end

    it "maps 404 responses as invalid subscriptions" do
      stub = StubPushEndpoint.new(404)
      result = StubClient.new(
        WebPush::VapidConfig.new(public_key: CLIENT_TEST_PUBLIC_KEY, private_key: CLIENT_TEST_PRIVATE_KEY, subject: CLIENT_TEST_SUBJECT),
        stub
      ).send(
        WebPush::Subscription.new(endpoint: "https://push.example/send", p256dh: CLIENT_TEST_P256DH, auth: CLIENT_TEST_AUTH),
        30,
        CLIENT_TEST_PAYLOAD
      )

      result.state.should eq(WebPush::Client::SendState::InvalidSubscription)
      result.status_code.should eq(404)
    end

    it "maps 410 responses as invalid subscriptions" do
      stub = StubPushEndpoint.new(410)
      result = StubClient.new(
        WebPush::VapidConfig.new(public_key: CLIENT_TEST_PUBLIC_KEY, private_key: CLIENT_TEST_PRIVATE_KEY, subject: CLIENT_TEST_SUBJECT),
        stub
      ).send(
        WebPush::Subscription.new(endpoint: "https://push.example/send", p256dh: CLIENT_TEST_P256DH, auth: CLIENT_TEST_AUTH),
        30,
        CLIENT_TEST_PAYLOAD
      )

      result.state.should eq(WebPush::Client::SendState::InvalidSubscription)
      result.status_code.should eq(410)
    end

    it "maps non-2xx and non-subscription-invalid responses as retryable" do
      stub = StubPushEndpoint.new(503)
      result = StubClient.new(
        WebPush::VapidConfig.new(public_key: CLIENT_TEST_PUBLIC_KEY, private_key: CLIENT_TEST_PRIVATE_KEY, subject: CLIENT_TEST_SUBJECT),
        stub
      ).send(
        WebPush::Subscription.new(endpoint: "https://push.example/send", p256dh: CLIENT_TEST_P256DH, auth: CLIENT_TEST_AUTH),
        30,
        CLIENT_TEST_PAYLOAD
      )

      result.state.should eq(WebPush::Client::SendState::Retryable)
      result.status_code.should eq(503)
    end

    it "raises for empty payloads" do
      expect_raises(WebPush::ValidationError, "Push encryption payload must not be empty") do
        StubClient.new(
          WebPush::VapidConfig.new(public_key: CLIENT_TEST_PUBLIC_KEY, private_key: CLIENT_TEST_PRIVATE_KEY, subject: CLIENT_TEST_SUBJECT),
          StubPushEndpoint.new(201)
        ).send(
          WebPush::Subscription.new(endpoint: "https://push.example/send", p256dh: CLIENT_TEST_P256DH, auth: CLIENT_TEST_AUTH),
          30,
          ""
        )
      end
    end
  end
end
