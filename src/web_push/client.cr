require "http/client"

module WebPush
  # Sends Web Push requests and maps provider responses into coarse result states.
  class Client
    # High-level outcome for an attempted send based on HTTP status.
    enum SendState
      Success
      Retryable
      InvalidSubscription
    end

    # HTTP response metadata returned from `Client#send`.
    struct SendResult
      getter state : SendState
      getter status_code : Int32
      getter body : String

      def initialize(@state : SendState, @status_code : Int32, @body : String)
      end
    end

    # Creates a client bound to a single VAPID configuration.
    def initialize(@vapid_config : VapidConfig)
    end

    # Sends a push request for a subscription.
    #
    # Returns a `SendResult` for HTTP responses:
    # - `Success` for `2xx`
    # - `InvalidSubscription` for `404` / `410`
    # - `Retryable` for all other non-`2xx`
    #
    # Raises `ValidationError` for invalid request inputs.
    # Network/transport errors from `HTTP::Client.exec` are not swallowed and
    # are raised to the caller.
    def send(subscription : Subscription, payload : String, *, ttl : Int32, expires_at : Time = Time.utc + Vapid::DEFAULT_EXPIRATION, now : Time = Time.utc) : SendResult
      request = RequestBuilder.push(subscription, @vapid_config, payload, ttl: ttl, expires_at: expires_at, now: now)
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
