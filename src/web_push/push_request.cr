require "http/headers"

module WebPush
  # Serialized HTTP request data ready to POST to a push endpoint.
  struct PushRequest
    getter endpoint : String
    getter headers : HTTP::Headers
    getter body : String

    def initialize(@endpoint : String, @headers : HTTP::Headers, @body : String = "")
    end
  end
end
