# web-push

Lightweight Crystal primitives for Web Push request validation, VAPID auth, request assembly, and delivery.

## Installation

1. Add the dependency to your `shard.yml`:

   ```yaml
   dependencies:
     web-push:
       github: your-github-user/web-push
   ```

2. Install shards:

   ```bash
   shards install
   ```

## Quick Start

### 1. Generate VAPID keys

This shard expects VAPID keys as base64url strings (`public_key` = 65-byte uncompressed P-256 key, `private_key` = 32 bytes). One easy option:

```bash
npx web-push generate-vapid-keys
```

### 2. Get a browser subscription

Persist the browser `PushSubscription` JSON and pass it to your backend. Both flattened and nested `keys` shapes are accepted.

```json
{
  "endpoint": "https://fcm.googleapis.com/fcm/send/abc123",
  "keys": {
    "p256dh": "BNnjgxL7iRJVGG2WfKoCcEas8uXFYFw4b6ivLqWsMp8pMhmdN3LRYQTyFWuE_MOCSD_OLdj2K2gtH3ggUe4nYeY",
    "auth": "KsWb025fekARlsIkDa5Vnw"
  }
}
```

### 3. Send a push notification (end-to-end minimal example)

```crystal
require "web-push"

subscription = WebPush::Subscription.from_json(
  %({"endpoint":"https://fcm.googleapis.com/fcm/send/abc123","keys":{"p256dh":"BNnjgxL7iRJVGG2WfKoCcEas8uXFYFw4b6ivLqWsMp8pMhmdN3LRYQTyFWuE_MOCSD_OLdj2K2gtH3ggUe4nYeY","auth":"KsWb025fekARlsIkDa5Vnw"}})
)

vapid_config = WebPush::VapidConfig.new(
  public_key: "BNpReHjFgbvl8tsrMoRJl-eKTIhYQXUsVPgIMGB2AUUG-ufq4N6F4FRsBiphNVCrkXGB5EPExzQoa6Qzng0yxyU",
  private_key: "79Om5Okowk6Tkd-1moexy7bIXuQQb5o2J9SWPq75Wnw",
  subject: "mailto:admin@example.com"
)

client = WebPush::Client.new(vapid_config)

result = client.send(subscription, %({"title":"Hello","body":"Production-ready push"}), ttl: 60)

case result.state
when WebPush::Client::SendState::Success
  puts "Delivered (#{result.status_code})"
when WebPush::Client::SendState::InvalidSubscription
  puts "Subscription expired or deleted, remove it from storage"
when WebPush::Client::SendState::TemporaryFailure
  puts "Retry later with backoff (status=#{result.status_code})"
when WebPush::Client::SendState::PermanentFailure
  puts "Request rejected permanently, inspect payload/auth/config (status=#{result.status_code})"
end
```

### 4. No-payload delivery

Use an empty payload string to send a no-payload push:

```crystal
client.send(subscription, "", ttl: 60)
```

## API Expectations

- `WebPush::Subscription` requires non-empty `endpoint`, `p256dh`, and `auth`.
- `WebPush::VapidConfig` requires:
  - base64url `public_key` that decodes to a 65-byte uncompressed P-256 key.
  - base64url `private_key` that decodes to 32 bytes.
  - `subject` starting with `mailto:` or `https://`.
- `WebPush::Client#send` requires `ttl >= 0`.
- Invalid input raises `WebPush::ValidationError`.
- HTTP responses map to `WebPush::Client::SendResult` states and helpers:
  - `Success` for `2xx`.
  - `InvalidSubscription` for `404` or `410`.
  - `TemporaryFailure` for `408`, `425`, `429`, and `5xx` responses.
  - `PermanentFailure` for remaining non-`2xx` responses.
  - `cleanup_subscription?` returns `true` only for `InvalidSubscription`.
  - `retryable?` returns `true` only for `TemporaryFailure`.
- Transport failures (DNS/connect/timeouts/TLS) bubble up from `HTTP::Client.exec` as exceptions; handle them in your worker/job runner.

## Compatibility Matrix (Expectations)

This shard builds standards-compliant Web Push requests (VAPID + RFC8291 payload encryption). Compatibility depends on the push service behind each browser family:

| Browser family | Typical push service | Expected behavior |
| --- | --- | --- |
| Chrome / Edge / Chromium browsers | Firebase Cloud Messaging (`fcm.googleapis.com`) | Expected to work with standard Web Push subscriptions and VAPID auth. |
| Firefox | Mozilla Autopush (`updates.push.services.mozilla.com`) | Expected to work with standard Web Push subscriptions and VAPID auth. |
| Safari (macOS + iOS/iPadOS) | Apple Web Push (`web.push.apple.com`) | Expected to work for Safari Web Push subscriptions with VAPID auth. |

## Security and Operational Caveats

- Keep VAPID private keys secret (env vars/secret manager/HSM if available). Never expose private keys to clients.
- Keep the VAPID public key stable for active subscriptions. Key rotation usually requires client re-subscription.
- JWT expiration is constrained to `<= 24h` and defaults to `12h`; pass `expires_at` only when you need tighter control.
- `ttl` is provider interpreted. Keep TTLs explicit and conservative for time-sensitive messages.
- Remove subscriptions from your datastore when `SendResult.cleanup_subscription?` is `true` (`404`/`410`).
- For `TemporaryFailure` responses (`SendResult.retryable?`), use exponential backoff and provider-specific rate limiting safeguards.
- Treat `PermanentFailure` responses as non-retryable request/config errors unless provider documentation says otherwise.
- Provider payload limits vary. Keep payloads compact; send IDs and fetch richer content in-app when possible.
- Production endpoints are HTTPS; validate and store subscription data exactly as provided by the browser.

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
