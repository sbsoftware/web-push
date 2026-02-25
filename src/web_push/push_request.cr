require "http/headers"

module WebPush
  struct PushRequest
    getter endpoint : String
    getter headers : HTTP::Headers
    getter body : String

    def initialize(@endpoint : String, @headers : HTTP::Headers, @body : String = "")
    end
  end
end
