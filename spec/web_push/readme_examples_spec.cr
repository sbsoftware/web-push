require "../spec_helper"

private README_TEST_PUBLIC_KEY        = "BNpReHjFgbvl8tsrMoRJl-eKTIhYQXUsVPgIMGB2AUUG-ufq4N6F4FRsBiphNVCrkXGB5EPExzQoa6Qzng0yxyU"
private README_TEST_PRIVATE_KEY       = "79Om5Okowk6Tkd-1moexy7bIXuQQb5o2J9SWPq75Wnw"
private README_TEST_SUBSCRIPTION_JSON = %({"endpoint":"https://fcm.googleapis.com/fcm/send/abc123","keys":{"p256dh":"BNnjgxL7iRJVGG2WfKoCcEas8uXFYFw4b6ivLqWsMp8pMhmdN3LRYQTyFWuE_MOCSD_OLdj2K2gtH3ggUe4nYeY","auth":"KsWb025fekARlsIkDa5Vnw"}})

private class ReadmeStubClient < WebPush::Client
  getter last_request : WebPush::PushRequest?

  def initialize(vapid_config : WebPush::VapidConfig, @status_code : Int32, @response_body : String = %({"status":"ok"}))
    super(vapid_config)
  end

  private def send_request(request : WebPush::PushRequest) : HTTP::Client::Response
    @last_request = WebPush::PushRequest.new(endpoint: request.endpoint, headers: request.headers.dup, body: request.body)
    HTTP::Client::Response.new(@status_code, body: @response_body)
  end
end

describe "README examples" do
  it "runs the minimal end-to-end payload send flow" do
    result = ReadmeStubClient.new(
      WebPush::VapidConfig.new(public_key: README_TEST_PUBLIC_KEY, private_key: README_TEST_PRIVATE_KEY, subject: "mailto:admin@example.com"),
      201
    ).send(
      WebPush::Subscription.from_json(README_TEST_SUBSCRIPTION_JSON),
      %({"title":"Hello","body":"Production-ready push"}),
      ttl: 60,
      now: Time.unix(1_710_000_000),
      expires_at: Time.unix(1_710_000_000) + 1.hour
    )

    result.state.should eq(WebPush::Client::SendState::Success)
    result.status_code.should eq(201)
    result.body.should eq(%({"status":"ok"}))
  end

  it "supports no-payload sends and invalid subscription cleanup flows" do
    no_payload_client = ReadmeStubClient.new(
      WebPush::VapidConfig.new(public_key: README_TEST_PUBLIC_KEY, private_key: README_TEST_PRIVATE_KEY, subject: "mailto:admin@example.com"),
      201
    )
    no_payload_result = no_payload_client.send(WebPush::Subscription.from_json(README_TEST_SUBSCRIPTION_JSON), "", ttl: 60)

    no_payload_result.state.should eq(WebPush::Client::SendState::Success)
    no_payload_client.last_request.not_nil!.body.should eq("")
    no_payload_client.last_request.not_nil!.headers.has_key?("Content-Encoding").should be_false

    invalid_subscription_result = ReadmeStubClient.new(
      WebPush::VapidConfig.new(public_key: README_TEST_PUBLIC_KEY, private_key: README_TEST_PRIVATE_KEY, subject: "mailto:admin@example.com"),
      410
    ).send(WebPush::Subscription.from_json(README_TEST_SUBSCRIPTION_JSON), %({"title":"Hello"}), ttl: 60)

    invalid_subscription_result.state.should eq(WebPush::Client::SendState::InvalidSubscription)
    invalid_subscription_result.status_code.should eq(410)
  end
end
