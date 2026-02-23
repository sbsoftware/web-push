require "../spec_helper"

describe WebPush::Subscription do
  describe ".new" do
    it "builds a subscription with valid fields" do
      subscription = WebPush::Subscription.new(
        endpoint: "https://push.example/abc",
        p256dh: "p256dh-key",
        auth: "auth-key"
      )

      subscription.endpoint.should eq("https://push.example/abc")
      subscription.p256dh.should eq("p256dh-key")
      subscription.auth.should eq("auth-key")
    end

    it "raises an explicit error for missing endpoint" do
      expect_raises(WebPush::ValidationError, "Subscription field 'endpoint' is required") do
        WebPush::Subscription.new(endpoint: "", p256dh: "p256dh", auth: "auth")
      end
    end

    it "raises an explicit error for missing p256dh" do
      expect_raises(WebPush::ValidationError, "Subscription field 'p256dh' is required") do
        WebPush::Subscription.new(endpoint: "https://push.example", p256dh: " ", auth: "auth")
      end
    end

    it "raises an explicit error for missing auth" do
      expect_raises(WebPush::ValidationError, "Subscription field 'auth' is required") do
        WebPush::Subscription.new(endpoint: "https://push.example", p256dh: "p256dh", auth: "")
      end
    end
  end

  describe ".from_json" do
    it "parses flattened subscription fields" do
      subscription = WebPush::Subscription.from_json(
        %({"endpoint":"https://push.example/abc","p256dh":"k1","auth":"k2"})
      )

      subscription.endpoint.should eq("https://push.example/abc")
      subscription.p256dh.should eq("k1")
      subscription.auth.should eq("k2")
    end

    it "parses keys nested under keys object" do
      subscription = WebPush::Subscription.from_json(
        %({"endpoint":"https://push.example/abc","keys":{"p256dh":"k1","auth":"k2"}})
      )

      subscription.p256dh.should eq("k1")
      subscription.auth.should eq("k2")
    end

    it "raises an explicit error when endpoint is missing" do
      expect_raises(WebPush::ValidationError, "Subscription field 'endpoint' is required") do
        WebPush::Subscription.from_json(%({"p256dh":"k1","auth":"k2"}))
      end
    end

    it "raises an explicit error when p256dh is not a string" do
      expect_raises(WebPush::ValidationError, "Subscription field 'p256dh' must be a string") do
        WebPush::Subscription.from_json(%({"endpoint":"https://push.example/abc","p256dh":1,"auth":"k2"}))
      end
    end

    it "raises an explicit error for invalid JSON" do
      expect_raises(WebPush::ValidationError, /Invalid subscription JSON/) do
        WebPush::Subscription.from_json("{")
      end
    end
  end

  describe "#to_json" do
    it "serializes to JSON" do
      subscription = WebPush::Subscription.new(
        endpoint: "https://push.example/abc",
        p256dh: "p256dh-key",
        auth: "auth-key"
      )

      JSON.parse(subscription.to_json).should eq(
        JSON.parse(%({"endpoint":"https://push.example/abc","p256dh":"p256dh-key","auth":"auth-key"}))
      )
    end
  end
end
