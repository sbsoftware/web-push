# web-push

Lightweight Crystal models for generic Web Push request data.

This shard currently includes:
- `WebPush::Subscription`
- `WebPush::Message`
- `WebPush::VapidConfig`
- `WebPush::Vapid`
- `WebPush::RequestBuilder`
- `WebPush::Client`

`WebPush::Client#send` and `WebPush::RequestBuilder.push` support both no-payload delivery and RFC8291 encrypted payload delivery.

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

vapid_config = WebPush::VapidConfig.new(
  public_key: "base64url-vapid-public",
  private_key: "base64url-vapid-private",
  subject: "mailto:admin@example.com"
)

client = WebPush::Client.new(vapid_config)

# No-payload Web Push
client.send(subscription, "", ttl: 60)

# Encrypted payload Web Push
client.send(subscription, %({"title":"Hello"}), ttl: 60)
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
