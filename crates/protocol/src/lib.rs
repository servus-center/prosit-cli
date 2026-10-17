//! Prosit v1: canonical signed records, RFC 9180 key wrapping, and encrypted events.
use aes_gcm::{
    Aes256Gcm, KeyInit, Nonce,
    aead::{Aead, Payload},
};
use anyhow::{Context, Result, bail, ensure};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use hpke::{
    Deserializable, Kem as KemTrait, OpModeR, OpModeS, Serializable, aead::AesGcm256,
    kdf::HkdfSha256, kem::X25519HkdfSha256,
};
use rand::{RngCore, SeedableRng, rngs::StdRng};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use zeroize::{Zeroize, ZeroizeOnDrop};

pub const VERSION: u32 = 1;
pub const MAX_PAYLOAD: usize = 16 * 1024;
pub const MAX_ENVELOPE: usize = 256 * 1024;
pub const MAX_TTL: i64 = 7 * 24 * 3600;
pub const VAULT_ITERATIONS: u32 = 600_000;
pub type Kem = X25519HkdfSha256;
pub fn b64(bytes: impl AsRef<[u8]>) -> String {
    URL_SAFE_NO_PAD.encode(bytes)
}
pub fn unb64(s: &str) -> Result<Vec<u8>> {
    Ok(URL_SAFE_NO_PAD.decode(s)?)
}
pub fn random_bytes<const N: usize>() -> [u8; N] {
    let mut x = [0; N];
    rand::rng().fill_bytes(&mut x);
    x
}
pub fn token() -> String {
    b64(random_bytes::<32>())
}
pub fn hash(bytes: impl AsRef<[u8]>) -> String {
    b64(Sha256::digest(bytes))
}
pub fn now() -> i64 {
    chrono::Utc::now().timestamp()
}
pub fn canonical<T: Serialize>(value: &T) -> Result<Vec<u8>> {
    Ok(serde_jcs::to_vec(value)?)
}
pub fn domain<T: Serialize>(kind: &str, value: &T) -> Result<Vec<u8>> {
    let mut bytes = format!("prosit:{kind}:v1\0").into_bytes();
    bytes.extend(canonical(value)?);
    Ok(bytes)
}

#[derive(Clone, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
#[serde(deny_unknown_fields)]
pub struct Secrets {
    pub signing: String,
    pub encryption: String,
}
impl Secrets {
    pub fn generate() -> Self {
        let (sk, _) = Kem::gen_keypair(&mut StdRng::from_os_rng());
        Self {
            signing: b64(random_bytes::<32>()),
            encryption: b64(sk.to_bytes()),
        }
    }
    pub fn public(&self) -> Result<PublicKeys> {
        let signing = SigningKey::from_bytes(
            &unb64(&self.signing)?
                .try_into()
                .map_err(|_| anyhow::anyhow!("bad signing key"))?,
        );
        let sk = <Kem as KemTrait>::PrivateKey::from_bytes(&unb64(&self.encryption)?)?;
        Ok(PublicKeys {
            signing: b64(signing.verifying_key().as_bytes()),
            encryption: b64(Kem::sk_to_pk(&sk).to_bytes()),
        })
    }
    pub fn sign<T: Serialize + Clone>(&self, kind: &str, data: T) -> Result<Signed<T>> {
        let key = SigningKey::from_bytes(
            &unb64(&self.signing)?
                .try_into()
                .map_err(|_| anyhow::anyhow!("bad signing key"))?,
        );
        Ok(Signed {
            signature: b64(key.sign(&domain(kind, &data)?).to_bytes()),
            data,
        })
    }
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct PublicKeys {
    pub signing: String,
    pub encryption: String,
}
impl PublicKeys {
    pub fn validate(&self) -> Result<()> {
        VerifyingKey::from_bytes(
            &unb64(&self.signing)?
                .try_into()
                .map_err(|_| anyhow::anyhow!("bad public key"))?,
        )?;
        let pk = unb64(&self.encryption)?;
        ensure!(
            pk.len() == 32 && pk.iter().any(|x| *x != 0),
            "invalid encryption key"
        );
        <Kem as KemTrait>::PublicKey::from_bytes(&pk)?;
        Ok(())
    }
    pub fn fingerprint(&self) -> Result<String> {
        Ok(hash(domain("identity", self)?))
    }
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Signed<T> {
    pub data: T,
    pub signature: String,
}
pub fn verify<T: Serialize>(kind: &str, record: &Signed<T>, public: &str) -> Result<()> {
    let key = VerifyingKey::from_bytes(
        &unb64(public)?
            .try_into()
            .map_err(|_| anyhow::anyhow!("bad verifying key"))?,
    )?;
    let sig = Signature::from_slice(&unb64(&record.signature)?)?;
    key.verify_strict(&domain(kind, &record.data)?, &sig)
        .context("invalid signature")
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Identity {
    pub user_id: String,
    pub keys: PublicKeys,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Device {
    pub user_id: String,
    pub id: String,
    pub name: String,
    pub keys: PublicKeys,
    pub read: bool,
    pub publish_circles: Vec<String>,
    pub created_at: i64,
}
impl Device {
    /// Human posts use the account root key through its reserved vault recipient.
    /// A device name or plaintext source field never establishes human authorship.
    pub fn is_human(&self, root: &Identity) -> bool {
        self.user_id == root.user_id
            && self.id == format!("web:{}", root.user_id)
            && self.keys == root.keys
            && self.read
            && self.publish_circles.is_empty()
            && self.name == "Web vault"
    }
    pub fn can_publish(&self, circle: &str) -> bool {
        self.publish_circles.iter().any(|x| x == "*" || x == circle)
    }
}
/// Prosit-specific device authorization, inspired by RFC 8628 (not OAuth).
/// The runtime generates both secrets; only their verifiers cross initiation.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct AuthorizationRequest {
    pub id: String,
    pub origin: String,
    pub account: String,
    pub name: String,
    pub keys: PublicKeys,
    pub read: bool,
    pub publish: bool,
    pub access_seconds: i64,
    pub expires_at: i64,
    pub device_code_hash: String,
    pub token_hash: String,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct AuthorizationProof {
    pub id: String,
    pub origin: String,
    pub action: String,
    pub issued_at: i64,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct AuthorizationApproval {
    pub request: AuthorizationRequest,
    pub user_id: String,
    pub certificate: Signed<Device>,
    pub expires_at: i64,
    pub setup: KeyWrap,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Directory {
    pub user_id: String,
    pub revision: i64,
    pub devices: Vec<Signed<Device>>,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Trust {
    pub owner_id: String,
    pub friend: Identity,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct CipherBlob {
    pub nonce: String,
    pub ciphertext: String,
}
pub fn encrypt_blob(key: &[u8], data: &[u8], aad: &[u8]) -> Result<CipherBlob> {
    let nonce = random_bytes::<12>();
    let cipher = Aes256Gcm::new_from_slice(key).map_err(|_| anyhow::anyhow!("invalid key"))?;
    let ciphertext = cipher
        .encrypt(Nonce::from_slice(&nonce), Payload { msg: data, aad })
        .map_err(|_| anyhow::anyhow!("encryption failed"))?;
    Ok(CipherBlob {
        nonce: b64(nonce),
        ciphertext: b64(ciphertext),
    })
}
pub fn decrypt_blob(key: &[u8], blob: &CipherBlob, aad: &[u8]) -> Result<Vec<u8>> {
    let nonce = unb64(&blob.nonce)?;
    ensure!(nonce.len() == 12, "invalid nonce");
    let cipher = Aes256Gcm::new_from_slice(key).map_err(|_| anyhow::anyhow!("invalid key"))?;
    cipher
        .decrypt(
            Nonce::from_slice(&nonce),
            Payload {
                msg: &unb64(&blob.ciphertext)?,
                aad,
            },
        )
        .map_err(|_| anyhow::anyhow!("decryption failed"))
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Circle {
    pub id: String,
    pub owner_id: String,
    pub revision: i64,
    pub members: Vec<Identity>,
    pub metadata: CipherBlob,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CircleMetadata {
    pub name: String,
    pub description: String,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Audience {
    pub circle: Signed<Circle>,
    pub directories: Vec<Signed<Directory>>,
    pub roots: Vec<Identity>,
    pub digest: String,
}
impl Audience {
    pub fn validate(&self, owner: &Identity) -> Result<Vec<Device>> {
        verify("circle", &self.circle, &owner.keys.signing)?;
        ensure!(
            self.circle.data.owner_id == owner.user_id,
            "wrong circle owner"
        );
        let mut roots: BTreeMap<String, PublicKeys> = self
            .circle
            .data
            .members
            .iter()
            .map(|m| (m.user_id.clone(), m.keys.clone()))
            .collect();
        roots.insert(owner.user_id.clone(), owner.keys.clone());
        ensure!(
            roots.len() == self.circle.data.members.len() + 1,
            "duplicate audience member"
        );
        ensure!(
            self.directories.len() == roots.len(),
            "incomplete directory set"
        );
        let mut seen = BTreeSet::new();
        let mut devices = Vec::new();
        for directory in &self.directories {
            let uid = &directory.data.user_id;
            ensure!(seen.insert(uid), "duplicate directory");
            let root = roots.get(uid).context("unexpected audience user")?;
            verify("directory", directory, &root.signing)?;
            for cert in &directory.data.devices {
                verify("device", cert, &root.signing)?;
                ensure!(&cert.data.user_id == uid, "incorrect device owner");
                cert.data.keys.validate()?;
                if cert.data.read {
                    devices.push(cert.data.clone());
                }
            }
        }
        ensure!(
            self.digest == audience_digest(&self.circle, &self.directories)?,
            "incorrect audience digest"
        );
        devices.sort_by(|a, b| a.id.cmp(&b.id));
        ensure!(
            devices.windows(2).all(|w| w[0].id != w[1].id),
            "duplicate device id"
        );
        Ok(devices)
    }
}
pub fn audience_digest(
    circle: &Signed<Circle>,
    directories: &[Signed<Directory>],
) -> Result<String> {
    let mut dirs = directories.to_vec();
    dirs.sort_by(|a, b| a.data.user_id.cmp(&b.data.user_id));
    Ok(hash(domain("audience", &(circle, dirs))?))
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct KeyWrap {
    pub enc: String,
    pub ciphertext: String,
}
pub fn wrap_key(public: &str, plaintext: &[u8], context: &[u8]) -> Result<KeyWrap> {
    let pk = <Kem as KemTrait>::PublicKey::from_bytes(&unb64(public)?)?;
    let (enc, mut ctx) = hpke::setup_sender::<AesGcm256, HkdfSha256, Kem, _>(
        &OpModeS::Base,
        &pk,
        context,
        &mut StdRng::from_os_rng(),
    )?;
    Ok(KeyWrap {
        enc: b64(enc.to_bytes()),
        ciphertext: b64(ctx.seal(plaintext, context)?),
    })
}
pub fn unwrap_key(secret: &str, wrapped: &KeyWrap, context: &[u8]) -> Result<Vec<u8>> {
    let sk = <Kem as KemTrait>::PrivateKey::from_bytes(&unb64(secret)?)?;
    let enc = <Kem as KemTrait>::EncappedKey::from_bytes(&unb64(&wrapped.enc)?)?;
    let mut ctx =
        hpke::setup_receiver::<AesGcm256, HkdfSha256, Kem>(&OpModeR::Base, &sk, &enc, context)?;
    Ok(ctx.open(&unb64(&wrapped.ciphertext)?, context)?)
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Header {
    pub version: u32,
    pub id: String,
    pub actor_id: String,
    pub device_id: String,
    pub circle_id: String,
    pub audience_digest: String,
    pub expires_at: i64,
    pub kind: String,
    pub replaces: Option<String>,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Envelope {
    pub header: Header,
    pub payload: CipherBlob,
    pub recipients: BTreeMap<String, KeyWrap>,
}
pub fn seal_event(
    secrets: &Secrets,
    header: Header,
    recipients: &[Device],
    plaintext: &serde_json::Value,
) -> Result<Signed<Envelope>> {
    let data = canonical(plaintext)?;
    ensure!(data.len() <= MAX_PAYLOAD, "payload too large");
    let mut key = random_bytes::<32>();
    let aad = domain("payload", &header)?;
    let payload = encrypt_blob(&key, &data, &aad)?;
    let mut wraps = BTreeMap::new();
    for recipient in recipients {
        let ctx = domain("wrap", &(&header, &recipient.id))?;
        wraps.insert(
            recipient.id.clone(),
            wrap_key(&recipient.keys.encryption, &key, &ctx)?,
        );
    }
    key.zeroize();
    secrets.sign(
        "event",
        Envelope {
            header,
            payload,
            recipients: wraps,
        },
    )
}
pub fn open_event(
    secrets: &Secrets,
    device_id: &str,
    event: &Signed<Envelope>,
    author: &Signed<Device>,
    root: &Identity,
) -> Result<serde_json::Value> {
    let h = &event.data.header;
    ensure!(h.version == VERSION, "unsupported crypto version");
    ensure!(
        (h.kind == "event" && h.replaces.is_none())
            || (h.kind == "withdrawal" && h.replaces.is_some()),
        "invalid envelope kind"
    );
    verify("device", author, &root.keys.signing)?;
    ensure!(
        author.data.user_id == root.user_id
            && h.actor_id == root.user_id
            && h.device_id == author.data.id,
        "wrong sender"
    );
    ensure!(
        author.data.can_publish(&h.circle_id) || author.data.is_human(root),
        "publisher lacks circle capability"
    );
    verify("event", event, &author.data.keys.signing)?;
    let wrap = event
        .data
        .recipients
        .get(device_id)
        .context("not a recipient")?;
    let mut key = unwrap_key(&secrets.encryption, wrap, &domain("wrap", &(h, device_id))?)?;
    let result = decrypt_blob(&key, &event.data.payload, &domain("payload", h)?);
    key.zeroize();
    let mut plaintext = result?;
    let value = serde_json::from_slice(&plaintext)?;
    plaintext.zeroize();
    Ok(value)
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FeedItem {
    pub sequence: i64,
    pub event: Signed<Envelope>,
    pub author: Signed<Device>,
    pub root: Identity,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FeedPage {
    pub items: Vec<FeedItem>,
    pub cursor: String,
    pub has_more: bool,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Vault {
    pub version: u32,
    pub iterations: u32,
    pub salt: String,
    pub blob: CipherBlob,
}
pub fn lock_vault<T: Serialize>(data: &T, passphrase: &str) -> Result<Vault> {
    ensure!(
        passphrase.len() >= 12,
        "vault passphrase must contain at least 12 characters"
    );
    let salt = random_bytes::<16>();
    let mut key = [0; 32];
    pbkdf2::pbkdf2_hmac::<Sha256>(passphrase.as_bytes(), &salt, VAULT_ITERATIONS, &mut key);
    let mut bytes = serde_json::to_vec(data)?;
    let blob = encrypt_blob(&key, &bytes, b"prosit:vault:v1");
    key.zeroize();
    bytes.zeroize();
    Ok(Vault {
        version: VERSION,
        iterations: VAULT_ITERATIONS,
        salt: b64(salt),
        blob: blob?,
    })
}
pub fn unlock_vault<T: serde::de::DeserializeOwned>(vault: &Vault, passphrase: &str) -> Result<T> {
    ensure!(
        vault.version == VERSION && vault.iterations == VAULT_ITERATIONS,
        "unsupported vault parameters"
    );
    let salt = unb64(&vault.salt)?;
    ensure!(salt.len() == 16, "invalid vault salt");
    let mut key = [0; 32];
    pbkdf2::pbkdf2_hmac::<Sha256>(passphrase.as_bytes(), &salt, vault.iterations, &mut key);
    let plaintext = decrypt_blob(&key, &vault.blob, b"prosit:vault:v1");
    key.zeroize();
    let mut bytes = plaintext?;
    let result = serde_json::from_slice(&bytes);
    bytes.zeroize();
    Ok(result?)
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Policy {
    pub version: u32,
    pub id: String,
    pub circles: Vec<String>,
    pub event_types: Vec<String>,
    pub source_kinds: Vec<String>,
    pub max_ttl_seconds: i64,
    pub allow_location: bool,
    pub approved: bool,
}
impl Policy {
    pub fn validate(&self) -> Result<()> {
        ensure!(
            self.version == VERSION && !self.id.is_empty(),
            "invalid policy version/id"
        );
        ensure!(
            !self.circles.is_empty()
                && !self.event_types.is_empty()
                && !self.source_kinds.is_empty(),
            "empty policy"
        );
        ensure!(
            self.event_types
                .iter()
                .all(|t| ["status", "activity", "availability"].contains(&t.as_str())),
            "unsupported event type"
        );
        ensure!((1..=MAX_TTL).contains(&self.max_ttl_seconds), "invalid TTL");
        Ok(())
    }
    pub fn check(
        &self,
        event: &serde_json::Value,
        circle: &str,
        actor: &str,
        clock: i64,
    ) -> Result<i64> {
        self.validate()?;
        ensure!(self.approved, "policy is not approved");
        ensure!(
            self.circles.iter().any(|c| c == circle),
            "circle not allowed by policy"
        );
        let obj = event.as_object().context("event must be an object")?;
        let allowed = [
            "schema_version",
            "logical_event_id",
            "type",
            "actor_id",
            "observed_at",
            "expires_at",
            "summary",
            "source",
            "availability",
            "location",
        ];
        ensure!(
            obj.keys().all(|k| allowed.contains(&k.as_str())),
            "unsupported event field"
        );
        ensure!(
            event["schema_version"] == VERSION && event["actor_id"] == actor,
            "wrong event version or actor"
        );
        ensure!(
            event["logical_event_id"]
                .as_str()
                .is_some_and(|s| !s.is_empty()),
            "missing logical event id"
        );
        ensure!(
            event["summary"]
                .as_str()
                .is_some_and(|s| !s.is_empty() && s.len() <= 4000),
            "invalid summary"
        );
        let kind = event["type"].as_str().context("missing type")?;
        ensure!(
            self.event_types.iter().any(|s| s == kind),
            "event type not permitted"
        );
        let source = event["source"]["kind"]
            .as_str()
            .context("missing source kind")?;
        ensure!(
            self.source_kinds.iter().any(|s| s == source),
            "source not permitted"
        );
        ensure!(
            ["explicit", "inferred"].contains(&event["source"]["basis"].as_str().unwrap_or("")),
            "missing evidence basis"
        );
        if event.get("location").is_some() {
            ensure!(self.allow_location, "location not permitted");
            ensure!(
                event["location"]["precision"].is_string(),
                "missing location precision"
            );
        }
        let observed = timestamp(&event["observed_at"])?;
        let expires = timestamp(&event["expires_at"])?;
        ensure!(
            observed <= clock + 60
                && expires > clock
                && expires > observed
                && expires - observed <= self.max_ttl_seconds,
            "stale or invalid validity window"
        );
        if kind == "availability" {
            let start = timestamp(&event["availability"]["starts_at"])?;
            let end = timestamp(&event["availability"]["ends_at"])?;
            ensure!(
                end > start && end <= expires && event["availability"]["timezone"].is_string(),
                "invalid availability"
            );
        }
        ensure!(canonical(event)?.len() <= MAX_PAYLOAD, "payload too large");
        Ok(expires)
    }
}
pub fn timestamp(v: &serde_json::Value) -> Result<i64> {
    Ok(
        chrono::DateTime::parse_from_rfc3339(v.as_str().context("expected RFC3339 timestamp")?)?
            .timestamp(),
    )
}
pub fn validate_envelope(event: &Signed<Envelope>, clock: i64) -> Result<()> {
    let e = &event.data;
    let h = &e.header;
    ensure!(
        h.version == VERSION && uuid::Uuid::parse_str(&h.id).is_ok(),
        "unsupported envelope version/id"
    );
    ensure!(
        h.expires_at > clock && h.expires_at <= clock + MAX_TTL,
        "invalid expiry"
    );
    ensure!(
        h.kind == "event" || h.kind == "withdrawal",
        "invalid envelope kind"
    );
    ensure!(
        (h.kind == "withdrawal") == h.replaces.is_some(),
        "invalid withdrawal reference"
    );
    ensure!(
        unb64(&e.payload.nonce)?.len() == 12 && unb64(&e.payload.ciphertext)?.len() >= 16,
        "invalid payload"
    );
    ensure!(
        !e.recipients.is_empty() && e.recipients.len() <= 606,
        "invalid recipients"
    );
    for wrap in e.recipients.values() {
        ensure!(
            unb64(&wrap.enc)?.len() == 32 && unb64(&wrap.ciphertext)?.len() == 48,
            "invalid wrapped key"
        );
    }
    if canonical(event)?.len() > MAX_ENVELOPE {
        bail!("envelope too large")
    }
    Ok(())
}
