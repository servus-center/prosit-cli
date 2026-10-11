use super::*;

#[derive(Serialize, Deserialize)]
pub struct Pending {
    request: Signed<AuthorizationRequest>,
    device_code: String,
    user_code: Option<String>,
    #[serde(default = "default_interval")]
    interval: u64,
    #[serde(default)]
    next_poll_at: i64,
    #[serde(default)]
    prepared: bool,
}
fn default_interval() -> u64 {
    5
}
fn instructions(p: &Pending) -> Result<Value> {
    Ok(
        json!({"status":"authorization_pending","verification_uri":format!("{}/activate",p.request.data.origin),
        "user_code":p.user_code,"fingerprint":p.request.data.keys.fingerprint()?,"expires_at":p.request.data.expires_at,
        "next_step":"Open the URL, sign in to the requested account, enter the code and compare the fingerprint. Then run prosit auth resume. This code grants no access."}),
    )
}
fn terminal(status: &str) -> Value {
    let next = match status {
        "connected" => "Connected. Enrollment does not approve a sharing policy or publication.",
        "access_denied" => {
            "The request was denied or the account/device was revoked. Start with a new profile if you want to try again."
        }
        "cancelled" => "Request cancelled. Start with a new profile if you want to try again.",
        "expired_token" => {
            "The request expired. Start with a new profile; remove any unredeemed device from Agents."
        }
        "slow_down" => "Throttled. Wait at least 60 seconds before running prosit auth resume.",
        "invalid_response" => {
            "Approval could not be verified. Do not publish; cancel and check the service and account."
        }
        _ => {
            "Authorization interrupted. The encrypted profile is saved; run prosit auth resume to continue."
        }
    };
    json!({"status":status,"next_step":next})
}
pub async fn connect(store: &Store, command: &Command) -> Result<Value> {
    let Command::Auth {
        command:
            AuthCommand::Connect {
                server,
                account,
                name,
                read,
                publish,
                access_seconds,
                allow_insecure_http,
            },
    } = command
    else {
        unreachable!()
    };
    ensure!(
        !store.home.join("vault.json").exists(),
        "Profile already exists; use auth resume or a new --home"
    );
    ensure!(*read || *publish, "Request --read, --publish, or both");
    ensure!(
        (3600..=90 * 86400).contains(access_seconds),
        "Access duration must be between 3600 and 7776000 seconds"
    );
    let server = check_server(server, *allow_insecure_http)?;
    let secrets = Secrets::generate();
    let keys = secrets.public()?;
    let device_id = uuid::Uuid::new_v4().to_string();
    let raw = token();
    let device_code = token();
    let request = secrets.sign(
        "authorization-request",
        AuthorizationRequest {
            id: device_id.clone(),
            origin: server.clone(),
            account: account.clone(),
            name: name.clone(),
            keys: keys.clone(),
            read: *read,
            publish: *publish,
            access_seconds: *access_seconds,
            expires_at: now() + 600,
            device_code_hash: hash(&device_code),
            token_hash: hash(&raw),
        },
    )?;
    let mut state = LocalState {
        version: VERSION,
        server,
        user_id: String::new(),
        device_id,
        token: raw,
        secrets,
        root: Identity {
            user_id: String::new(),
            keys,
        },
        metadata_key: None,
        pairing_id: None,
        authorization: Some(Pending {
            request,
            device_code,
            user_code: None,
            interval: 5,
            next_poll_at: 0,
            prepared: false,
        }),
        certificate: None,
        policies: vec![],
        pins: BTreeMap::new(),
        revisions: BTreeMap::new(),
        outbox: BTreeMap::new(),
    };
    // Save secrets before the network request. A lost response is recoverable with resume.
    store.save(&state)?;
    match initiate(store, &mut state).await {
        Ok(()) => instructions(state.authorization.as_ref().unwrap()),
        Err(e) => Ok(network_status(&e)),
    }
}
async fn initiate(store: &Store, state: &mut LocalState) -> Result<()> {
    let p = state
        .authorization
        .as_ref()
        .context("No pending authorization")?;
    let mut api = Api::new(state)?;
    api.token.clear();
    let response = api
        .post("/api/v1/device-authorizations", &p.request)
        .await?;
    ensure!(
        response["verification_uri"] == format!("{}/activate", state.server),
        "Invalid verification origin"
    );
    let code = response["user_code"]
        .as_str()
        .context("Missing user code")?;
    ensure!(
        code.len() == 9
            && code.bytes().enumerate().all(|(i, b)| if i == 4 {
                b == b'-'
            } else {
                b"ABCDEFGHJKLMNPQRSTUVWXYZ23456789".contains(&b)
            }),
        "Invalid user code"
    );
    state.authorization.as_mut().unwrap().user_code = Some(code.into());
    store.save(state)
}
fn network_status(error: &anyhow::Error) -> Value {
    if error
        .downcast_ref::<RemoteError>()
        .is_some_and(|e| e.status == 429)
    {
        terminal("slow_down")
    } else {
        terminal("interrupted")
    }
}
async fn runtime(state: &LocalState, action: &str) -> Result<Value> {
    let p = state
        .authorization
        .as_ref()
        .context("No pending authorization")?;
    let proof = state.secrets.sign(
        "authorization-proof",
        AuthorizationProof {
            id: state.device_id.clone(),
            origin: state.server.clone(),
            action: action.into(),
            issued_at: now(),
        },
    )?;
    let mut api = Api::new(state)?;
    api.token.clone_from(&p.device_code);
    api.post(&format!("/api/v1/device-authorizations/{action}"), &proof)
        .await
}
fn accept(state: &mut LocalState, response: Value) -> Result<()> {
    let p = state
        .authorization
        .as_ref()
        .context("No pending authorization")?;
    let identity: Signed<Identity> = serde_json::from_value(response["identity"].clone())?;
    verify("identity", &identity, &identity.data.keys.signing)?;
    let approval: Signed<AuthorizationApproval> =
        serde_json::from_value(response["approval"].clone())?;
    verify(
        "authorization-approval",
        &approval,
        &identity.data.keys.signing,
    )?;
    let a = &approval.data;
    let cert = &a.certificate;
    verify("device", cert, &identity.data.keys.signing)?;
    let directory: Signed<Directory> = serde_json::from_value(response["directory"].clone())?;
    verify("directory", &directory, &identity.data.keys.signing)?;
    ensure!(
        a.request == p.request.data
            && a.request.origin == state.server
            && a.request.keys == state.secrets.public()?
            && a.user_id == identity.data.user_id
            && cert.data.user_id == a.user_id
            && cert.data.id == state.device_id
            && cert.data.keys == a.request.keys
            && cert.data.name == a.request.name
            && (!cert.data.read || a.request.read)
            && (cert.data.publish_circles.is_empty() || a.request.publish)
            && !cert.data.publish_circles.iter().any(|c| c == "*")
            && (cert.data.read || !cert.data.publish_circles.is_empty())
            && cert.data.created_at <= now() + 60
            && cert.data.created_at >= now() - 600
            && a.expires_at > now()
            && a.expires_at <= cert.data.created_at + a.request.access_seconds
            && a.request.expires_at > now()
            && directory.data.user_id == a.user_id
            && directory
                .data
                .devices
                .iter()
                .filter(|d| d.data.id == state.device_id)
                .eq(std::iter::once(cert)),
        "Approval binding mismatch"
    );
    let bytes = Zeroizing::new(unwrap_key(
        &state.secrets.encryption,
        &a.setup,
        &domain("authorization-setup", &a.request)?,
    )?);
    let config: Value = serde_json::from_slice(&bytes)?;
    let metadata = config["metadata_key"]
        .as_str()
        .context("Missing metadata key")?;
    ensure!(unb64(metadata)?.len() == 32, "Invalid metadata key");
    state.user_id = a.user_id.clone();
    state.root = identity.data;
    state.metadata_key = Some(metadata.into());
    state.certificate = Some(cert.clone());
    state
        .revisions
        .insert(state.user_id.clone(), directory.data.revision);
    state.authorization.as_mut().unwrap().prepared = true;
    Ok(())
}
pub async fn resume(store: &Store, state: &mut LocalState, timeout: u64) -> Result<Value> {
    let p = state
        .authorization
        .as_ref()
        .context("No pending authorization")?;
    if p.user_code.is_none() {
        if p.request.data.expires_at <= now() {
            return Ok(terminal("expired_token"));
        }
        if let Err(e) = initiate(store, state).await {
            return Ok(network_status(&e));
        }
        return instructions(state.authorization.as_ref().unwrap());
    }
    let started = std::time::Instant::now();
    loop {
        let p = state.authorization.as_ref().unwrap();
        if p.prepared {
            // The request row may have been purged after a lost redemption
            // acknowledgement. Its absence must not strand an active profile.
            match Api::new(state)?.get("/api/v1/me").await {
                Ok(user) if user["id"] == state.user_id => {
                    state.authorization = None;
                    store.save(state)?;
                    return Ok(terminal("connected"));
                }
                Ok(_) => return Ok(terminal("invalid_response")),
                Err(error)
                    if error
                        .downcast_ref::<RemoteError>()
                        .is_some_and(|e| e.status == 401) => {}
                Err(error) => return Ok(network_status(&error)),
            }
            if p.request.data.expires_at <= now() {
                return Ok(terminal("expired_token"));
            }
            let response = match runtime(state, "redeem").await {
                Ok(v) => v,
                Err(e) => return Ok(network_status(&e)),
            };
            if matches!(response["status"].as_str(), Some("connected" | "redeemed")) {
                // 'redeemed' handles a lost acknowledgement, without issuing a second credential.
                match Api::new(state)?.get("/api/v1/me").await {
                    Ok(user) if user["id"] == state.user_id => {}
                    Ok(_) => return Ok(terminal("invalid_response")),
                    Err(error)
                        if error
                            .downcast_ref::<RemoteError>()
                            .is_some_and(|e| e.status == 401) =>
                    {
                        return Ok(terminal("access_denied"));
                    }
                    Err(error) => return Ok(network_status(&error)),
                }
                state.authorization = None;
                store.save(state)?;
                return Ok(terminal("connected"));
            }
            return Ok(known_status(&response));
        }
        if p.request.data.expires_at <= now() {
            return Ok(terminal("expired_token"));
        }
        let delay = p.next_poll_at.saturating_sub(now()).max(0) as u64;
        if delay > 0 {
            if started.elapsed().as_secs() + delay > timeout {
                return Ok(terminal("interrupted"));
            }
            tokio::select! {
                _ = tokio::time::sleep(Duration::from_secs(delay)) => {},
                _ = tokio::signal::ctrl_c() => return Ok(terminal("interrupted")),
            }
        }
        // Persist the next deadline before polling, including across interrupted processes.
        let p = state.authorization.as_mut().unwrap();
        p.next_poll_at = now() + p.interval as i64;
        store.save(state)?;
        let response = tokio::select! {
            result = runtime(state,"poll") => match result { Ok(v)=>v,Err(e)=>return Ok(network_status(&e)) },
            _ = tokio::signal::ctrl_c() => return Ok(terminal("interrupted")),
        };
        match response["status"].as_str() {
            Some("approved") => {
                if accept(state, response).is_err() {
                    return Ok(terminal("invalid_response"));
                }
                store.save(state)?; // Durable before one-time redemption.
            }
            Some("authorization_pending" | "slow_down") => {
                let interval = response["interval"].as_u64().unwrap_or(60).clamp(5, 60);
                let p = state.authorization.as_mut().unwrap();
                p.interval = p.interval.max(interval);
                p.next_poll_at = now() + p.interval as i64;
                store.save(state)?;
                if started.elapsed().as_secs() >= timeout {
                    return Ok(known_status(&response));
                }
            }
            _ => return Ok(known_status(&response)),
        }
    }
}
fn known_status(response: &Value) -> Value {
    match response["status"].as_str() {
        Some("access_denied") => terminal("access_denied"),
        Some("expired_token") => terminal("expired_token"),
        Some("cancelled") => terminal("cancelled"),
        Some("slow_down") => terminal("slow_down"),
        Some("authorization_pending") => {
            json!({"status":"authorization_pending","next_step":"Approve in the browser, then run prosit auth resume."})
        }
        _ => terminal("invalid_response"),
    }
}
pub async fn cancel(store: &Store, state: &mut LocalState) -> Result<Value> {
    ensure!(
        state.authorization.is_some(),
        "No pending browser authorization"
    );
    let response = match runtime(state, "cancel").await {
        Ok(v) => v,
        Err(e) => return Ok(network_status(&e)),
    };
    if response["status"] == "cancelled" {
        state.authorization = None;
        state.token.clear();
        state.certificate = None;
        store.save(state)?;
    }
    Ok(known_status(&response))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn public_instructions_and_errors_never_serialize_private_state_or_remote_text() {
        let secret = Secrets::generate();
        let device_code = token();
        let credential = token();
        let pending = Pending {
            request: secret
                .sign(
                    "authorization-request",
                    AuthorizationRequest {
                        id: "test-id".into(),
                        origin: "https://prosit.example".into(),
                        account: "alice".into(),
                        name: "Test".into(),
                        keys: secret.public().unwrap(),
                        read: true,
                        publish: false,
                        access_seconds: 86400,
                        expires_at: now() + 600,
                        device_code_hash: hash(&device_code),
                        token_hash: hash(&credential),
                    },
                )
                .unwrap(),
            device_code: device_code.clone(),
            user_code: Some("ABCD-EFGH".into()),
            interval: 5,
            next_poll_at: 0,
            prepared: false,
        };
        let output = instructions(&pending).unwrap().to_string();
        for sensitive in [
            &device_code,
            &credential,
            &secret.signing,
            &secret.encryption,
        ] {
            assert!(!output.contains(sensitive));
        }
        assert!(!output.contains("token_hash") && !output.contains("device_code_hash"));
        let response =
            json!({"status":device_code,"error":{"code":credential},"secret":secret.signing});
        assert_eq!(known_status(&response), terminal("invalid_response"));
        let error = anyhow::Error::new(RemoteError {
            status: 500,
            code: credential,
        });
        assert_eq!(network_status(&error), terminal("interrupted"));
    }
}
