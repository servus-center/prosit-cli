use prosit_protocol::*;
use serde_json::{Value, json};
fn fixture(name: &str) -> Value {
    serde_json::from_str(
        &std::fs::read_to_string(format!(
            "{}/../../tests/fixtures/{name}",
            env!("CARGO_MANIFEST_DIR")
        ))
        .unwrap(),
    )
    .unwrap()
}
#[test]
fn rust_and_javascript_envelopes_decrypt_and_authenticate() {
    for filename in ["rust.json", "javascript.json"] {
        let f = fixture(filename);
        let secret: Secrets = serde_json::from_value(f["receiver"].clone()).unwrap();
        let event: Signed<Envelope> = serde_json::from_value(f["event"].clone()).unwrap();
        let author: Signed<Device> = serde_json::from_value(f["author"].clone()).unwrap();
        let root: Identity = serde_json::from_value(f["root"].clone()).unwrap();
        assert_eq!(
            open_event(&secret, "bob-device", &event, &author, &root).unwrap(),
            f["plaintext"]
        );
        let wrong = Secrets::generate();
        assert!(open_event(&wrong, "bob-device", &event, &author, &root).is_err());
        assert!(open_event(&secret, "outsider", &event, &author, &root).is_err());
        let mut changed = event.clone();
        changed.data.header.circle_id = "another".into();
        assert!(open_event(&secret, "bob-device", &changed, &author, &root).is_err());
        let mut changed = event.clone();
        changed.data.payload.ciphertext.push('A');
        assert!(open_event(&secret, "bob-device", &changed, &author, &root).is_err());
        let mut bad_root = root.clone();
        bad_root.keys = wrong.public().unwrap();
        assert!(open_event(&secret, "bob-device", &event, &author, &bad_root).is_err());
        let vault: Vault = serde_json::from_value(f["vault"].clone()).unwrap();
        assert_eq!(
            unlock_vault::<Value>(&vault, "fixture-passphrase-not-a-secret").unwrap(),
            json!({"fixture":true})
        );
        assert!(unlock_vault::<Value>(&vault, "wrong password").is_err());
    }
}
#[test]
fn policies_fail_closed() {
    let clock = 1700000000;
    let mut policy = Policy {
        version: 1,
        id: "approved".into(),
        circles: vec!["friends".into()],
        event_types: vec!["status".into()],
        source_kinds: vec!["user_statement".into()],
        max_ttl_seconds: 3600,
        allow_location: false,
        approved: true,
    };
    let event = json!({"schema_version":1,"logical_event_id":"id","type":"status","actor_id":"alice","summary":"hello","observed_at":"2023-11-14T22:13:20Z","expires_at":"2023-11-14T23:13:20Z","source":{"kind":"user_statement","basis":"explicit"}});
    assert!(policy.check(&event, "friends", "alice", clock).is_ok());
    assert!(policy.check(&event, "family", "alice", clock).is_err());
    assert!(policy.check(&event, "friends", "bob", clock).is_err());
    assert!(
        policy
            .check(&event, "friends", "alice", clock + 3601)
            .is_err()
    );
    let mut extra = event.clone();
    extra["location"] = json!({"precision":"exact","lat":1});
    assert!(policy.check(&extra, "friends", "alice", clock).is_err());
    extra = event.clone();
    extra["raw_email"] = json!("private");
    assert!(policy.check(&extra, "friends", "alice", clock).is_err());
    policy.approved = false;
    assert!(policy.check(&event, "friends", "alice", clock).is_err());
}
#[test]
fn malformed_crypto_input_never_panics() {
    assert!(
        decrypt_blob(
            &[0; 32],
            &CipherBlob {
                nonce: "AA".into(),
                ciphertext: "".into()
            },
            b""
        )
        .is_err()
    );
    assert!(
        verify(
            "test",
            &Signed {
                data: json!({}),
                signature: "broken".into()
            },
            "broken"
        )
        .is_err()
    );
}
