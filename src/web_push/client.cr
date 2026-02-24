require "http/client"

module WebPush
  alias RequestExecutor = Proc(String, String, HTTP::Headers, String, HTTP::Client::Response)

  class Client
    enum SendState
      Success
      Retryable
      InvalidSubscription
    end

    struct SendResult
      getter state : SendState
      getter status_code : Int32
      getter body : String

      def initialize(@state : SendState, @status_code : Int32, @body : String)
      end
    end

    def initialize(@vapid_config : VapidConfig, @request_executor : RequestExecutor = Client.default_request_executor)
    end

    def send_no_payload(subscription : Subscription, ttl : Int32, *, expires_at : Time = Time.utc + Vapid::DEFAULT_EXPIRATION, now : Time = Time.utc) : SendResult
      request = RequestBuilder.no_payload_push(subscription, @vapid_config, ttl, expires_at: expires_at, now: now)
      response = @request_executor.call("POST", request.endpoint, request.headers, request.body)
      SendResult.new(state: map_state(response.status_code), status_code: response.status_code, body: response.body)
    end

    private def self.default_request_executor : RequestExecutor
      ->(method : String, endpoint : String, headers : HTTP::Headers, body : String) { HTTP::Client.exec(method, endpoint, headers, body) }
    end

    private def map_state(status_code : Int32) : SendState
      return SendState::Success if status_code >= 200 && status_code < 300

      # Web Push providers signal an expired or deleted endpoint with these codes.
      return SendState::InvalidSubscription if status_code == 404 || status_code == 410

      SendState::Retryable
    end
  end
end
