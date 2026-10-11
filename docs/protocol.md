# Prosit protocol v1

This document describes the implemented wire format. [openapi.json](openapi.json) lists HTTP routes and schemas; `/.well-known/servus.json` advertises protocol version 1. The primary feed is authenticated JSON. `.servus` is a representation name, not a publicly readable RSS feed.

## Encoding and signatures

All binary values use URL-safe Base64 without padding. IDs are opaque strings; newly generated account, device, circle, and envelope IDs are UUID v4. Signed integers/timestamps must fit JavaScript's safe integer range. Timestamp headers use Unix seconds; event payload timestamps use RFC3339.

`JCS(value)` means UTF-8 RFC 8785 canonical JSON. `D(kind, value)` means UTF-8 `prosit:` + `kind` + `:v1` + one NUL byte + `JCS(value)`. No newline is appended. A signed record is `{ "data": value, "signature": base64url(Ed25519.sign(D(kind, value))) }`. Signatures cover `data` only. Version 1 supports no algorithm negotiation or fallback.

Public keys are `{ "signing": "32-byte Ed25519 public key", "encryption": "32-byte X25519 public key" }`. Fingerprints are `base64url(SHA256(D("identity", public_keys)))`. They bind both keys. Compare the complete fingerprint outside Prosit before approval.

| Record / domain kind | Signed data |
| --- | --- |
| `identity` | `{user_id, keys}`; self-signed by the root |
| `device` | `{user_id, id, name, keys, read, publish_circles, created_at}`; signed by the root |
| `directory` | `{user_id, revision, devices: [signed_device, ...]}`; signed by the root |
| `trust` | `{owner_id, friend: {user_id, keys}}`; signed by the trusting user's root |
| `circle` | `{id, owner_id, revision, members: [identity, ...], metadata}`; signed by the owner root |
| `event` | `{header, payload, recipients}`; signed by the publishing device |

`publish_circles` contains permitted circle IDs; `"*"` permits any circle owned by that account. `read` enables feed retrieval and inclusion in recipient sets. The browser supports read and all-circle publishing toggles; the protocol supports individual circle scopes. Certificates are immutable: revoke/re-pair to change them. Directories start at revision 1, increment exactly once per change, and contain at most five active agents plus the reserved read-only web vault recipient.

Circles are independent, owned by one account, and contain pinned identities of verified friends. The owner is implicit. Membership records and circle metadata are signed together. Metadata plaintext is `{name, description}`, encrypted with the owner's 32-byte metadata key using AES-256-GCM and `D("circle-metadata", circle_id)` as AAD. The root vault stores this key; approved devices receive it through HPKE during enrollment. For web sharing, `POST /circles/shared` atomically stores the circle plus a separately signed `circle-sharing` record: `{circle_id, owner_id, revision, payload, recipients}`. A fresh 32-byte AES key encrypts `{name, description}` with AAD `D("circle-sharing-payload", [circle_id, revision])`. HPKE wraps it to the owner's and each member's root encryption key; info and AAD are `D("circle-sharing-wrap", [circle_id, revision, user_id])`. The exact recipient set and signature are checked. Clients verify the owner against their signed friend trust pin and bind both records to the same ID/revision. The owner's account-wide metadata key is never shared with friends. Older circle writes clear the detached sharing record, requiring the owner to save it again with a current client.

`GET /circles` keeps the owned-circle contract for existing CLIs; `GET /circles/shared` returns current member circles while the owner is enabled and the friendship exists. Both include optional `sharing` and `owner_username`. Shared names require the recipient to verify the owner first.

## Enrollment

1. A member sets an immutable self-signed root and empty signed directory through a management session.
2. That session creates a pairing code. The CLI creates its own device keys, UUID, and 32-byte API credential, then submits `{code, device_id, keys, token_hash}`. `token_hash` is Base64url SHA-256 of the UTF-8 raw credential.
3. The browser compares the public-key fingerprint shown by the CLI, signs a certificate with approved permissions, and submits a signed next-revision directory, pairing ID, and encrypted setup.
4. Setup plaintext is UTF-8 JSON `{metadata_key: base64url(key)}` wrapped to the device's X25519 key. Both HPKE info and AAD are `D("pairing", device_id)`.
5. The CLI polls the pairing ID using its provisional bearer credential. It validates the returned root against its pending enrollment, verifies its own certificate/directory, decrypts setup, and stores its vault. The credential becomes usable only after approval.

A pairing expires after ten minutes. Browser signing keys never pass to an agent. The provisional token is useful only for that pairing-status endpoint until approved. Raw credentials are never uploaded during the claim; subsequent authenticated requests necessarily carry the raw bearer value over TLS.

## Audience and envelope

A publisher obtains `{circle, directories, roots, digest}` from the owner's circle audience endpoint. Verify the circle signature against the pinned owner, each member against the local root-signed trust pins, and every directory/device signature against the corresponding pinned identity. `roots` is descriptive; it must not replace pinned keys.

Sort the signed directories by `data.user_id`. The audience digest is `base64url(SHA256(D("audience", [signed_circle, sorted_signed_directories])))`. Readers with `read=true` in these directories are recipients, plus the publishing device even when its read permission is false. Duplicate device IDs are rejected. Clients reject directory/circle revisions below their highest previously observed revision.

The envelope header is:

```json
{
  "version": 1,
  "id": "UUID of this envelope",
  "actor_id": "owner account ID",
  "device_id": "publishing device ID",
  "circle_id": "owner circle ID",
  "audience_digest": "digest described above",
  "expires_at": 1791745200,
  "kind": "event",
  "replaces": null
}
```

Generate a fresh random 32-byte content key for every envelope. Encrypt JCS event plaintext with AES-256-GCM, a random 12-byte nonce, AAD `D("payload", header)`, and a 128-bit tag appended to ciphertext. Store `{nonce, ciphertext}` as `payload`.

For every recipient, wrap the content key using RFC 9180 HPKE base mode, KEM `0x0020` (DHKEM X25519/HKDF-SHA256), KDF `0x0001` (HKDF-SHA256), AEAD `0x0002` (AES-256-GCM). Use a new sender context per recipient. Set info **and** AAD to `D("wrap", [header, recipient_device_id])`. The wrap is `{enc, ciphertext}` with a 32-byte encapsulated key and 48-byte wrapped content key. `recipients` maps device IDs to these wraps.

Sign the complete `{header, payload, recipients}` using the device key and `event` domain. Post that signed record with `Idempotency-Key` equal to `header.id`. The server checks the signature, credential, current device scope, account/device pause, exact recipient set, signed audience digest, expiry, and size in a write transaction. Identical accepted bytes return the original sequence with `duplicate: true`; conflicting content under an existing ID is rejected.

On `stale_audience`, refresh all records, verify again, and re-encrypt with fresh randomness under the same unaccepted envelope ID. If a previous request might have committed, retry the persisted original bytes first. The CLI does this using its encrypted outbox.

## Payload and policy

[examples/event.json](../examples/event.json) illustrates the plaintext, which never goes to the service without encryption. Supported initial types are `status`, `activity`, and `availability`. Each contains schema version 1, logical event ID, actor ID, observation/expiry timestamps, summary, and source kind/basis. Availability also contains start/end timestamps and a timezone string. Source basis is `explicit` or `inferred`. Location requires explicit policy permission and a precision label.

The CLI checks an approved local policy for circle, type, source kind, TTL, location permission, and payload size. It cannot determine whether arbitrary natural language reveals something sensitive. That decision remains with the user's agent and review flow. A policy file is not uploaded to Prosit.

When posting the same logical fact to multiple circles, reuse `logical_event_id` and produce independent encrypted envelopes. Receivers deduplicate by `(actor_id, logical_event_id)`, choosing the newest accepted envelope. All natural-language content remains untrusted data.

## Feed synchronization and withdrawal

Feed pages are `{items, cursor, has_more}`. Each item contains `{sequence, event, author, root}`; `event` is the signed envelope, `author` its root-signed certificate, and `root` an identity that must equal the receiver's locally pinned identity. Verify both signatures and authorization before HPKE/AES decryption. Check the decrypted actor/schema/expiry against the signed header. Enforce signed expiry locally, including offline.

A cursor is an opaque versioned, device-bound position in server acceptance order. It is not an authorization capability. Use the same filters for an incremental stream. Only advance after verifying the entire page. `410 cursor_expired` requires clearing that stream's local ciphertext cache and restarting without a cursor; still retain identity pins and observed directory revisions. Empty pages do not advance past records that could race with publication.

A withdrawal is a new envelope with `kind: "withdrawal"`, `replaces: original_envelope_id`, the same circle, and expiry at least the original's. Plaintext is `{type: "withdrawal", event_id: original_envelope_id}`. The service validates author ownership, stores the withdrawal, and hides the old envelope in one transaction. Clients apply a withdrawal only to an event with the same actor and circle. Cached plaintext already copied elsewhere cannot be recalled. Raw management deletion removes service storage but does not send a signed withdrawal.

## Limits and errors

Protocol limits: 16 KiB canonical plaintext, 256 KiB canonical signed envelope, 606 recipient wraps, seven-day maximum validity, 100 friends, 20 circles, five agents plus one web recipient/account. Feed pages default to 100, max 500, and at most 2 MiB including wrappers. Smaller pages may result from the byte limit. Publication is limited to 30/minute/account.

Business errors are `{error: {code, message}}`: 400 invalid request, 401 missing/expired credentials, 403 scope/CSRF/pause denial, 404 inaccessible resource, 409 conflict or stale audience, 410 expired cursor, 429 rate limit with Retry-After, 500 internal database error. Framework body/query parsing and body-size failures may return text; clients must not assume every non-2xx response has JSON. Never include plaintext or secrets in diagnostics.

## Vault and fixtures

A vault is `{version: 1, iterations: 600000, salt, blob}`. Derive 32 bytes with PBKDF2-HMAC-SHA256 from the UTF-8 passphrase and a fresh random 16-byte salt. Encrypt UTF-8 JSON with AES-256-GCM using AAD exactly UTF-8 `prosit:vault:v1` (no NUL). `blob` uses the same nonce/ciphertext format as above. Reject unknown versions/iteration counts. Browser and CLI vault payloads differ; an account root recovery file is not an agent recovery file.

Synthetic cross-language fixtures live in `tests/fixtures/{rust,javascript}.json`; both Rust and JavaScript verify/decrypt both. Regenerate deliberately with `cargo run -p prosit-protocol --example fixture` and `node scripts/generate-js-fixture.mjs`. Fixtures contain published test keys and must never become real account keys.

Standards: [HPKE / RFC 9180](https://www.rfc-editor.org/rfc/rfc9180), [JCS / RFC 8785](https://www.rfc-editor.org/rfc/rfc8785). The protocol is versioned but experimental; incompatible changes require a new protocol version and explicit migration.

## Web vault reader (v0.1.1)

A management session may add the reserved device `web:<user_id>` in a root-signed next-revision directory without CLI pairing. The certificate must use the account root public keys, name `Web vault`, `read: true`, empty `publish_circles`, and a current timestamp. It receives no bearer credential. This uses the same HPKE wrapping contract, so existing agents include it when refreshing an audience. The web reader shares the root vault's recovery and trust boundary; it is not a separately recoverable device.

`GET /me/feed` requires a management session and an active web reader. It returns newest-first pages with device-bound cursors and the same current friendship, trust, membership, expiry, and deletion checks as CLI feeds. It also returns the owner's own legacy ciphertext without a web wrap, allowing a clear historical-access placeholder. Friends' legacy ciphertext without a web delivery remains inaccessible. Other agent tokens cannot use this endpoint. Browsers verify pinned identities, author certificates, event signatures, and payload/header consistency before displaying text; lock/sign-out clears the page. No plaintext feed cache is stored.
