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

`publish_circles` contains permitted circle IDs; `"*"` permits any circle owned by that account. `read` enables feed retrieval and inclusion in recipient sets. Legacy pairing offers read/all-circle publishing toggles; browser verification-code approval requires selected individual circle scopes. Certificates are immutable: revoke/re-pair to change them. Directories start at revision 1, increment exactly once per change, and contain at most five active agents plus the reserved read-only web vault recipient.

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

For `rate_limited`, the error also includes `retry_after_seconds` (the remaining window, matching the `Retry-After` header) and `rate_limit_scope` (the limiter category, without account, address, or credential identifiers). Passkey requests with a verified web session use a 30/minute/account budget. Other passkey requests use a separate 30/minute/peer-IP budget; neither shares the legacy login/device-authorization peer budget. Existing conversion-password (10/5 minutes/account), enrollment-start (10/10 minutes/account name), and passkey-login (30/5 minutes/account name) limits still apply. A rejected request does not extend the blocking window.

## Vault and fixtures

A vault is `{version: 1, iterations: 600000, salt, blob}`. Derive 32 bytes with PBKDF2-HMAC-SHA256 from the UTF-8 passphrase and a fresh random 16-byte salt. Encrypt UTF-8 JSON with AES-256-GCM using AAD exactly UTF-8 `prosit:vault:v1` (no NUL). `blob` uses the same nonce/ciphertext format as above. Reject unknown versions/iteration counts. Browser and CLI vault payloads differ; an account root recovery file is not an agent recovery file.

Synthetic cross-language fixtures live in `tests/fixtures/{rust,javascript}.json`; both Rust and JavaScript verify/decrypt both. Regenerate deliberately with `cargo run -p prosit-protocol --example fixture` and `node scripts/generate-js-fixture.mjs`. Fixtures contain published test keys and must never become real account keys.

Standards: [HPKE / RFC 9180](https://www.rfc-editor.org/rfc/rfc9180), [JCS / RFC 8785](https://www.rfc-editor.org/rfc/rfc8785). The protocol is versioned but experimental; incompatible changes require a new protocol version and explicit migration.

## Web vault reader (v0.1.1)

A management session may add the reserved device `web:<user_id>` in a root-signed next-revision directory without CLI pairing. The certificate must use the account root public keys, name `Web vault`, `read: true`, empty `publish_circles`, and a current timestamp. It receives no bearer credential. This uses the same HPKE wrapping contract, so existing agents include it when refreshing an audience. The web reader shares the root vault's recovery and trust boundary; it is not a separately recoverable device.

`GET /me/feed` requires a management session and an active web reader. It returns newest-first pages with device-bound cursors and the same current friendship, trust, membership, expiry, and deletion checks as CLI feeds. It also returns the owner's own legacy ciphertext without a web wrap, allowing a clear historical-access placeholder. Friends' legacy ciphertext without a web delivery remains inaccessible. Other agent tokens cannot use this endpoint. Browsers verify pinned identities, author certificates, event signatures, and payload/header consistency before displaying text; lock/sign-out clears the page. No plaintext feed cache is stored.

## Browser verification-code authorization (v0.2.1)

This is a **Prosit-specific protocol inspired by [RFC 8628](https://www.rfc-editor.org/rfc/rfc8628.html)**, not an OAuth grant or OAuth-compatible token endpoint. It uses JSON, Prosit signatures and E2E enrollment, without refresh tokens. All paths below start with `/api/v1/device-authorizations`; mutations retain the normal CSRF/origin guards. TLS is required in production. Codes/secrets must not appear in URL parameters, access logs, shell arguments or diagnostics.

1. The persistent CLI generates device keys, a UUID, a 32-byte random private `device_code`, and a separate 32-byte API credential. It durably saves these in its encrypted profile **before** initiation. `POST /device-authorizations` receives `Signed<AuthorizationRequest>` with domain `authorization-request`: `{id, origin, account, name, keys, read, publish, access_seconds, expires_at, device_code_hash, token_hash}`. `account` is the exact login name, `origin` is the configured origin, request expiry is at most 600 seconds, and access duration is 3600–7776000 seconds. Both hashes are Base64url SHA-256 of UTF-8 secrets. The signature proves the initiating signing key. Identical initiation retries are idempotent; the same ID cannot change its bindings.
2. The service returns `{verification_uri, user_code, expires_at, interval}`. The verification URI is exactly `<origin>/activate`; the user code contains eight random characters from a 32-character alphabet, displayed `XXXX-XXXX` (40 bits). It is public request-selection information, not a credential. The CLI outputs only these public instructions and the key fingerprint. No private device code is returned to a model. The service stores its hash, while retaining the public user code for interrupted-initiation recovery.
3. A management session posts `{user_code}` to `/lookup`. Only the requested login account can look it up, and the request becomes bound to that immutable user ID. Lookup grants no access and returns the signed request, fingerprint and status. The browser verifies the signature, exact origin and account. `/deny` takes `{id}` and irreversibly denies that pending request.
4. The user compares the fingerprint, chooses read access, individual owned publishing circles and duration, then explicitly approves. Every permission starts unselected. Grants cannot exceed requested capabilities or duration; `*` is prohibited here. The browser signs a device certificate and next directory, wraps `{metadata_key}` to the initiating X25519 key with HPKE info/AAD `D("authorization-setup", request)`, and signs domain `authorization-approval` over `{request, user_id, certificate, expires_at, setup}`. `POST /approve` takes `{approval, directory}`. Exact request equality, ownership, root signatures, all device fields, durations, and directory continuity are checked atomically. Only one new device can be added; existing certificates cannot change. The root private keys never leave the browser. The account metadata key is intentionally granted to the approved runtime, as in legacy enrollment.
5. The CLI calls `/poll`, `/redeem`, or `/cancel` with the private device code in the Authorization bearer header **and** a signed `authorization-proof` body `{id, origin, action, issued_at}`. Proofs must match the initiating signing key, endpoint action, origin, and a 60-second clock window. A public code or a device code alone is insufficient. Polling starts at five seconds; early polls return `slow_down` and increase the interval by five seconds up to 60. The server enforces the deadline and the CLI persists it across processes. Polling may repeatedly return the encrypted approval until redemption, to recover lost responses.
6. The CLI verifies the signed root identity, approval, exact original request, certificate, scope and directory, and decrypts setup locally. It saves the prepared profile **before** `/redeem`. The service atomically changes approved → redeemed and activates exactly one credential with the browser-selected expiry. Replays/concurrent calls return `redeemed` without returning setup or creating credentials again. After a lost redemption response, the saved CLI checks its credential before retrying redemption and completes locally when it is active, even if the request row has already been purged. Polling and redemption never return a raw API credential: it was generated locally. Root identity trust is established over the exact configured HTTPS origin during first enrollment, as with legacy pairing; a compromised web application/origin is outside this threat model.

Statuses are `authorization_pending`, `approved` (private protocol response), `connected`, `access_denied`, `expired_token`, `cancelled`, `slow_down`, and `redeemed` (already consumed; no setup). The CLI converts transport failures/timeouts/Ctrl-C during polling into `interrupted`, invalid approvals into `invalid_response`, and never echoes arbitrary server status text. Authorization JSON statuses can have exit code 0; callers must inspect `status`. `auth connect` returns immediately and `auth resume` polls internally; process termination leaves the encrypted profile resumable. After denial/cancellation/expiry start in a fresh profile. Legacy profiles lacking the optional authorization state still deserialize and use `auth pair`/`auth resume` unchanged.

Initiation/polling/lookup are capped by the existing socket-IP limiter (30 requests/minute shared across auth endpoints). Initiation also has a service-wide limit of 300 per ten minutes; lookup permits ten attempts per management account per ten minutes. Proxy-forwarded IP headers are not trusted, so clients behind the same reverse proxy share the socket-IP limit. Limits are process-local and reset at restart; polling deadlines are in SQLite. Terminal requests/unused encrypted approvals are purged one day after request expiry. An approved but never redeemed device remains in the signed directory (the server cannot rewrite root signatures); remove it in Agents to reclaim a slot. Denial/cancel cannot change a redeemed credential; use device revocation instead. Enrollment does not approve a sharing policy, publication, scheduling, or stateless key storage.

## Passkey login and browser vault v2 (v0.3.0)

This storage format leaves the event/agent protocol at v1. WebAuthn is verified with webauthn-rs, user verification required, exact configured origin and hostname RP ID. Ceremony state exists only in SQLite and expires after ten minutes. HTTP mutation/CSRF and session rules still apply. A flow capability is random; its SHA-256 hash identifies server-side state. Each phase is consumed once, including failed attempts. Restart abandoned flows; a lost final response is recovered by normal passkey sign-in. New account/invite consumption and legacy password retirement occur only on final confirmation.

The vault envelope is `{version:2,user_id,fingerprint,revision:1,blob:CipherBlob}`. Its context `V` is those four fields excluding `blob`. A random 32-byte vault key encrypts the existing v1 plaintext browser payload `{version:1,user_id,secrets,metadata_key}` under AES-256-GCM with AAD `D("server-vault", V)`. Fingerprint uses the existing root-public-key fingerprint.

Each passkey has `{prf_salt,blob:CipherBlob}` wrapping that same vault key. `prf_salt` is 32 random bytes in base64url, generated by the server at enrollment and reused for that credential. The browser requests `prf.evalByCredential[credentialId].first = decode(prf_salt)` on authentication. Using PRF result bytes as IKM, derive 32 bytes with HKDF-SHA256, salt `decode(prf_salt)`, and info `D("passkey-wrap", W)`, where `W = {...V,credential_id}`. Encrypt the 32-byte vault key using AES-256-GCM and AAD `D("passkey-wrap", W)`. All AES nonces are fresh random 12-byte values. PRF output and unwrapped key material are never sent to Prosit.

v0.3.1 requests `prf.eval.first` for single-credential assertions, and retains `evalByCredential` for multiple credentials with distinct PRF salts. Registration also supplies an explicit `eval.first` input. Each browser ceremony has an explicit user action and can retry a browser cancellation before any server assertion is submitted.

For a provider without PRF, `/register` accepts `use_passphrase:true` and does not request PRF on the subsequent assertions. Its wrap is `{prf_salt,passphrase_kdf:"pbkdf2-sha256-600000",blob}`: the existing salt field now supplies PBKDF2-HMAC-SHA256 with 600,000 iterations and UTF-8 passphrase input, deriving a 32-byte AES key. Encrypt the same vault key using AES-256-GCM with AAD `D("passphrase-wrap", {...W,passphrase_kdf:"pbkdf2-sha256-600000"})`. The salt remains a random per-credential 32-byte value; nonces remain 12 random bytes. Unknown KDF markers or an unexpected wrapping method are rejected. Omission of `passphrase_kdf` retains the original PRF format. The passphrase is entered and re-entered only in the browser; it is never sent to the server. The final root proof covers the complete wrap, including the method marker. Passphrase fallback does not re-enable password authentication.

Enrollment calls `POST /auth/passkeys/enroll` (invitation/username, operator enrollment capability, or an authenticated account), then `/register` with a WebAuthn registration response. `/stage` verifies a first assertion and persists the encrypted envelope/wrap plus signed identity/directory. Its response reads the ciphertext back from SQLite and supplies a second authentication challenge. The browser independently decrypts this saved copy and signs `D("passkey-vault", {user_id,flow_id,credential_id,vault_hash,wrap_hash})`, where `flow_id=SHA256(flow capability)` and the other hashes are SHA-256 of canonical JSON. `/confirm` verifies the second assertion, root proof, account ownership, and unchanged identity/directory before activating storage. For backup passkeys, the existing ciphertext is immutable; only an additional encrypted vault-key copy is added.

Login uses `/auth/passkeys/login/start` and `/finish`; the latter issues a 12-hour HttpOnly session and never returns plaintext key material. `/me/vault/{credentialId}` returns the encrypted vault and selected wrap only to the owning browser session. `/me/passkeys` lists names/timestamps, and `DELETE /me/passkeys/{id}` revokes that key and its sessions while refusing to remove the last credential. Credential changes and account deletion require passkey verification within five minutes. Operator password reset and `/auth/login` cannot re-enable a converted account's password. Legacy password signup returns 410; legacy login and conversion remain until post-alpha cleanup.
