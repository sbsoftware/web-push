require "../spec_helper"

describe WebPush::Message do
  describe ".new" do
    it "builds a message with valid fields" do
      message = WebPush::Message.new(payload: %({"title":"Hello"}), ttl: 60)

      message.payload.should eq(%({"title":"Hello"}))
      message.ttl.should eq(60)
    end

    it "raises an explicit error for missing payload" do
      expect_raises(WebPush::ValidationError, "Message field 'payload' is required") do
        WebPush::Message.new(payload: " ", ttl: 60)
      end
    end

    it "raises an explicit error for negative ttl" do
      expect_raises(WebPush::ValidationError, "Message field 'ttl' must be greater than or equal to 0") do
        WebPush::Message.new(payload: "{}", ttl: -1)
      end
    end
  end

  describe ".from_json" do
    it "parses message JSON" do
      message = WebPush::Message.from_json(%({"payload":"{}","ttl":120}))

      message.payload.should eq("{}")
      message.ttl.should eq(120)
    end

    it "raises an explicit error when ttl is missing" do
      expect_raises(WebPush::ValidationError, "Message field 'ttl' is required") do
        WebPush::Message.from_json(%({"payload":"{}"}))
      end
    end

    it "raises an explicit error when ttl is not an integer" do
      expect_raises(WebPush::ValidationError, "Message field 'ttl' must be an integer") do
        WebPush::Message.from_json(%({"payload":"{}","ttl":"100"}))
      end
    end

    it "raises an explicit error for invalid JSON" do
      expect_raises(WebPush::ValidationError, /Invalid message JSON/) do
        WebPush::Message.from_json("{")
      end
    end
  end

  describe "#to_json" do
    it "serializes to JSON" do
      message = WebPush::Message.new(payload: %({"title":"Hello"}), ttl: 60)

      json = JSON.parse(message.to_json).as_h

      json["payload"].as_s.should eq(%({"title":"Hello"}))
      json["ttl"].as_i.should eq(60)
    end
  end
end
