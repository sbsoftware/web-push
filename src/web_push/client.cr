require "http/client"

module WebPush
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

    def initialize(@vapid_config : VapidConfig)
    end

    def send_no_payload(subscription : Subscription, ttl : Int32, *, expires_at : Time = Time.utc + Vapid::DEFAULT_EXPIRATION, now : Time = Time.utc) : SendResult
      request = RequestBuilder.no_payload_push(subscription, @vapid_config, ttl, expires_at: expires_at, now: now)
      response = send_request(request)
      SendResult.new(state: map_state(response.status_code), status_code: response.status_code, body: response.body)
    end

    private def send_request(request : PushRequest) : HTTP::Client::Response
      HTTP::Client.exec("POST", request.endpoint, request.headers, request.body)
    end

    private def map_state(status_code : Int32) : SendState
      return SendState::Success if status_code >= 200 && status_code < 300

      # Web Push providers signal an expired or deleted endpoint with these codes.
      return SendState::InvalidSubscription if status_code == 404 || status_code == 410

      SendState::Retryable
    end
  end
end
