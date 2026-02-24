# web-push

Lightweight Crystal models for generic Web Push request data.

This shard currently includes:
- `WebPush::Subscription`
- `WebPush::Message`
- `WebPush::VapidConfig`
- `WebPush::Vapid`

It does not include payload encryption or network delivery.

## Installation

1. Add the dependency to your `shard.yml`:

   ```yaml
   dependencies:
     web-push:
       github: your-github-user/web-push
   ```

2. Run `shards install`

## Usage

```crystal
require "web-push"
```

```crystal
subscription = WebPush::Subscription.new(
  endpoint: "https://push.example/send",
  p256dh: "base64-p256dh",
  auth: "base64-auth"
)

message = WebPush::Message.new(
  payload: %({"title":"Hello"}),
  ttl: 60
)
```

## Development

- Install dependencies: `shards install`
- Run specs: `crystal spec`
- Format code: `crystal tool format`

## Contributing

1. Fork it (<https://github.com/your-github-user/web-push/fork>)
2. Create your feature branch (`git checkout -b my-new-feature`)
3. Commit your changes (`git commit -am 'Add some feature'`)
4. Push to the branch (`git push origin my-new-feature`)
5. Create a new Pull Request

## Contributors

- [Stefan Bilharz](https://github.com/your-github-user) - creator and maintainer
