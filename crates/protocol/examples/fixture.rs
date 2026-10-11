use prosit_protocol::*;
use serde_json::json;
fn main() -> anyhow::Result<()> {
    let root = Secrets::generate();
    let sender = Secrets::generate();
    let receiver = Secrets::generate();
    let identity = Identity {
        user_id: "alice".into(),
        keys: root.public()?,
    };
    let author = root.sign(
        "device",
        Device {
            user_id: "alice".into(),
            id: "alice-device".into(),
            name: "fixture".into(),
            keys: sender.public()?,
            read: true,
            publish_circles: vec!["*".into()],
            created_at: 1700000000,
        },
    )?;
    let bob = Device {
        user_id: "bob".into(),
        id: "bob-device".into(),
        name: "fixture".into(),
        keys: receiver.public()?,
        read: true,
        publish_circles: vec![],
        created_at: 1700000000,
    };
    let content = json!({"summary":"Hello, friends — Grüße!","type":"status","number":42});
    let header = Header {
        version: 1,
        id: "a52c178a-28bb-41eb-ad07-0dc9788c5a2a".into(),
        actor_id: "alice".into(),
        device_id: author.data.id.clone(),
        circle_id: "circle".into(),
        audience_digest: "test-digest".into(),
        expires_at: 1800000000,
        kind: "event".into(),
        replaces: None,
    };
    let event = seal_event(&sender, header, std::slice::from_ref(&bob), &content)?;
    let vault = lock_vault(&json!({"fixture":true}), "fixture-passphrase-not-a-secret")?;
    println!(
        "{}",
        serde_json::to_string_pretty(
            &json!({"description":"Synthetic interoperability fixture. These private keys have never protected real data.","root":identity,"author":author,"sender":sender,"receiver":receiver,"recipient":bob,"event":event,"plaintext":content,"vault":vault})
        )?
    );
    Ok(())
}
