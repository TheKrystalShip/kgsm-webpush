# Changelog

All notable changes to `TheKrystalShip.KGSM.WebPush` are documented here.

## [Unreleased]

## [1.0.0] - 2026-08-12

### Added — the Web Push protocol, as a library

RFC 8291 message encryption over the RFC 8188 `aes128gcm` content encoding, RFC 8292 VAPID identity and
request signing, and the RFC 8030 delivery POST.

Extracted from `kgsm-api`, which had the only implementation, because a second surface now needs to send
a push and two implementations of message encryption is one more than anybody can keep correct. Each
consumer keeps its own subscriptions, preferences and staged actions — only the protocol is shared,
because two surfaces on one host have different users and different opinions about what is worth
sending, and sharing that state would be wrong.

**Zero dependencies, and the reason is narrower than tidiness:** this assembly encrypts messages, so
anything it referenced would be a dependency of the crypto in every surface that sends a push.
Everything needed is in the BCL on net10. That includes not taking a logger — a rejection comes back in
`PushResult` with the push service's own words and the caller logs it, being the only side that knows
whose device it was.

The VAPID JWT is written out rather than serialized from a record, so the assembly stays AOT-safe for
consumers that are AOT; `JsonEncodedText` does the escaping.

The tests decrypt what the sender produces, deriving the keys from the subscription's private half the
way a browser does, rather than re-using the sender's own idea of the format — an encoding mistake
produces bytes of the right length and the wrong message, and only a receiver catches that.
