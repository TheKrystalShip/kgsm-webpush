# TheKrystalShip.KGSM.WebPush

Web Push for KGSM surfaces, as a library with no state and no opinions about who is being notified.

- **RFC 8291** message encryption over the **RFC 8188** `aes128gcm` content encoding.
- **RFC 8292** VAPID: a P-256 identity for the sending host, and the `Authorization: vapid` header.
- **RFC 8030** delivery: the POST, and the one answer (404/410) that means a subscription is gone
  and the row should be deleted rather than retried.

## What it deliberately does not do

It holds no subscriptions, no preferences and no staged actions. A consumer keeps those in its own
store and hands this an endpoint, a key pair and some bytes. Two surfaces on one host have separate
users, separate opinions about what is worth sending, and separate keys — sharing the crypto is right,
sharing the state would be wrong.

It also **logs nothing**. Every failure comes back in `PushResult` carrying the push service's own
detail; the caller logs it, because the caller is the only side that knows whose device it was.

## Zero dependencies

Everything needed — P-256 ECDH, HKDF, AES-GCM, ES256 — is in the BCL on net10. The usual NuGet option
drags in BouncyCastle and Newtonsoft for the same work. This assembly encrypts messages, so anything it
referenced would become a dependency of the crypto in every surface that sends a push.

## Using it

```csharp
VapidKeyPair keys = VapidKeyPair.Generate();     // once per host, then FIXED — see below
var sender = new WebPushSender(httpClient);

PushResult result = await sender.SendAsync(
    new PushSubscription(endpoint, p256dh, auth),
    JsonSerializer.SerializeToUtf8Bytes(payload),
    keys,
    subject: "https://panel.example.com",        // how a push service reaches whoever runs this host
    ct);

switch (result.Outcome)
{
    case PushOutcome.Accepted: /* the SERVICE took it. Not "shown on a phone". */ break;
    case PushOutcome.Expired:  /* delete the row — it will never work again */    break;
    case PushOutcome.Failed:   /* count it; do not delete on one bad answer */    break;
}
```

⚠ **The key pair is fixed for the life of the host.** The public key is baked into every subscription a
browser creates, so rotating it silently invalidates every device already registered. Generate once,
persist, never regenerate.

⚠ **`Accepted` means the push service accepted the message.** It says nothing about whether a device
ever displayed it, and no surface built on this may claim otherwise.
