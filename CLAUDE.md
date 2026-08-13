# CLAUDE.md — kgsm-webpush

## What this is

`TheKrystalShip.KGSM.WebPush` — the Web Push protocol as a **dependency-free, AOT-safe library**. It is
not a leaf: it deploys nowhere, runs nothing, and holds no state.

- `WebPushCrypto` — RFC 8291 encryption over the RFC 8188 `aes128gcm` content encoding.
- `VapidKeyPair` / `VapidSigner` — RFC 8292: the host's P-256 identity and the `Authorization: vapid` header.
- `WebPushSender` — the RFC 8030 POST, and the one answer that means a subscription is gone.

## The line it draws

**The protocol is shared; the state is not.** A consumer keeps its own subscription table, its own
preferences and its own staged actions, and hands this an endpoint, a key pair and some bytes. Two
surfaces on one host have different users and different opinions about what is worth sending — the
Control Panel notifies about a fleet, the assistant about a confirmation somebody is waiting on — so a
shared store would force one answer where there are two.

## Rules

- **No dependencies.** This assembly encrypts messages; anything it referenced would become a dependency
  of the crypto in every surface that sends a push. Every primitive it needs (P-256 ECDH, HKDF, AES-GCM,
  ES256) is in the BCL. That includes **no logger** — failures come back in `PushResult`.
- **AOT-safe, and it must stay so.** A consumer may be Native AOT. No reflection, no reflection-based
  serializer: the VAPID JWT is written out with `JsonEncodedText` doing the escaping, deliberately.
- **`Accepted` is not "delivered".** It means the push service took the message. No surface built on this
  may claim a phone showed anything.

## Testing

`dotnet test kgsm-webpush.slnx`. The crypto tests are **receivers**: they derive the keys from the
subscription's private half and decrypt, per the RFC, rather than re-using the sender's idea of the
format. That is the only way the salt, record size, key-info labels and padding are actually checked —
an encoding mistake produces bytes of the right length and the wrong message, and a sender-side
assertion cannot see it.

⚠ The VAPID signature must be **fixed-width r‖s**, not DER. A DER signature is well-formed and every
push service rejects it: nothing throws, nothing is malformed, nothing arrives.

## Version tracking

- **Version source:** `<Version>` in `src/WebPush/WebPush.csproj`.
- Consumers pin a version from the org's GitHub Packages feed, so shipping a change means **publish + bump on
  both sides** — a same-version repack is served stale from the NuGet cache (keyed by id+version).
- Consumers: `kgsm-api`, `kgsm-llm`. Build both before declaring work done.
