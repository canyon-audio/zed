use crate::crypto::{self, KeyPair, SessionKeys};
use crate::protocol::*;
use anyhow::Result;
use base64::{engine::general_purpose::STANDARD as B64, Engine};
use futures::channel::mpsc;
use futures::{SinkExt, StreamExt};
use gpui::AppContext;
use gpui_tokio::Tokio;
use tokio::sync::watch;
use tokio_tungstenite::{connect_async_tls_with_config, tungstenite::Message, Connector};
use x25519_dalek::PublicKey;

/// Current pairing status, observable by UI.
#[derive(Debug, Clone)]
pub enum PairingStatus {
    Disconnected,
    Connecting,
    WaitingForMobile { join_code: String },
    KeyExchange,
    VerifySas { sas_code: String },
    Paired { pairing_id: String, peer_online: bool },
    Failed { reason: String },
}

/// Credentials to save/load from keychain.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct StoredCredentials {
    pub pairing_id: String,
    pub symmetric_key_b64: String,
    #[serde(default)]
    pub reconnect_token: Option<String>,
}

/// Manages the WebSocket connection to the ZRC relay server with E2E encryption.
pub struct RelayTransport {
    /// Send tap events to the relay (they get encrypted before sending).
    pub event_tx: mpsc::UnboundedSender<TapEvent>,
    /// Receive commands from the relay (decrypted from EncryptedEnvelopes).
    pub command_rx: mpsc::UnboundedReceiver<RelayCommand>,
    /// Observable pairing status.
    pub status_rx: watch::Receiver<PairingStatus>,
    /// Channel to receive credentials that should be saved to keychain.
    pub credential_save_rx: mpsc::UnboundedReceiver<StoredCredentials>,
    /// Channel signaling that stale credentials should be deleted from keychain.
    pub credential_delete_rx: mpsc::UnboundedReceiver<()>,
    /// Notified when the mobile peer (re)connects, so tap can resync thread state.
    pub peer_connected_rx: mpsc::UnboundedReceiver<()>,
}

impl RelayTransport {
    /// Connect to the relay server and spawn read/write loops.
    pub fn connect(
        url: &str,
        stored_credentials: Option<StoredCredentials>,
        cx: &impl AppContext,
    ) -> Result<Self> {
        let (event_tx, event_rx) = mpsc::unbounded::<TapEvent>();
        let (command_tx, command_rx) = mpsc::unbounded::<RelayCommand>();
        let (status_tx, status_rx) = watch::channel(PairingStatus::Disconnected);
        let (cred_save_tx, cred_save_rx) = mpsc::unbounded::<StoredCredentials>();
        let (cred_delete_tx, cred_delete_rx) = mpsc::unbounded::<()>();
        let (peer_connected_tx, peer_connected_rx) = mpsc::unbounded::<()>();

        let url = url.to_string();
        let client_id = uuid::Uuid::new_v4().to_string();

        Tokio::spawn(
            cx,
            run_connection_loop(
                url,
                client_id,
                stored_credentials,
                event_rx,
                command_tx,
                status_tx,
                cred_save_tx,
                cred_delete_tx,
                peer_connected_tx,
            ),
        )
        .detach();

        Ok(Self {
            event_tx,
            command_rx,
            status_rx,
            credential_save_rx: cred_save_rx,
            credential_delete_rx: cred_delete_rx,
            peer_connected_rx,
        })
    }
}

async fn run_connection_loop(
    url: String,
    client_id: String,
    stored_credentials: Option<StoredCredentials>,
    mut event_rx: mpsc::UnboundedReceiver<TapEvent>,
    mut command_tx: mpsc::UnboundedSender<RelayCommand>,
    status_tx: watch::Sender<PairingStatus>,
    mut cred_save_tx: mpsc::UnboundedSender<StoredCredentials>,
    cred_delete_tx: mpsc::UnboundedSender<()>,
    peer_connected_tx: mpsc::UnboundedSender<()>,
) {
    let mut reconnect_token: Option<String> = stored_credentials
        .as_ref()
        .and_then(|c| c.reconnect_token.clone());

    let mut session_keys: Option<SessionKeys> = stored_credentials.and_then(|creds| {
        let key_bytes = B64.decode(&creds.symmetric_key_b64).ok()?;
        if key_bytes.len() != 32 {
            return None;
        }
        let mut key = [0u8; 32];
        key.copy_from_slice(&key_bytes);
        Some(SessionKeys::new(creds.pairing_id, key))
    });

    loop {
        let _ = status_tx.send(PairingStatus::Connecting);
        log::info!("zrc: connecting to relay at {url}");

        let tls_connector = if url.starts_with("wss://") {
            let tls_config = http_client_tls::tls_config();
            Some(Connector::Rustls(std::sync::Arc::new(tls_config)))
        } else {
            None
        };

        match connect_async_tls_with_config(&url, None, false, tls_connector).await {
            Ok((ws_stream, _)) => {
                log::info!("zrc: connected to relay");
                let (mut ws_sink, mut ws_source) = ws_stream.split();

                // Phase 1: Handshake (include reconnect_token if we have one)
                let handshake = ClientHandshake::new_zed(
                    &client_id,
                    session_keys.as_ref().map(|k| k.pairing_id.as_str()),
                    reconnect_token.as_deref(),
                );
                if send_json(&mut ws_sink, &handshake).await.is_err() {
                    continue;
                }

                // Phase 2: Pairing or Reconnect
                let mut peeked_message: Option<String> = None;

                if session_keys.is_none() {
                    match run_pairing(&mut ws_sink, &mut ws_source, &status_tx).await {
                        Ok((keys, token)) => {
                            reconnect_token = token;
                            // Save credentials for reconnection
                            let _ = cred_save_tx
                                .send(StoredCredentials {
                                    pairing_id: keys.pairing_id.clone(),
                                    symmetric_key_b64: B64.encode(keys.symmetric_key),
                                    reconnect_token: reconnect_token.clone(),
                                })
                                .await;
                            session_keys = Some(keys);
                        }
                        Err(e) => {
                            log::warn!("zrc: pairing failed: {e}");
                            let _ = status_tx.send(PairingStatus::Failed {
                                reason: e.to_string(),
                            });
                            tokio::time::sleep(std::time::Duration::from_secs(5)).await;
                            continue;
                        }
                    }
                } else {
                    let keys = session_keys.as_ref().unwrap();
                    log::info!("zrc: reconnecting with stored pairing {}", keys.pairing_id);

                    // Brief peek for pairing.expired; preserve any other message
                    match tokio::time::timeout(
                        std::time::Duration::from_secs(2),
                        ws_source.next(),
                    )
                    .await
                    {
                        Ok(Some(Ok(Message::Text(text)))) => {
                            match RelayMessage::parse(&text) {
                                Ok(RelayMessage::PairingExpired { .. }) => {
                                    log::warn!("zrc: stored pairing expired, clearing credentials");
                                    session_keys = None;
                                    reconnect_token = None;
                                    let _ = cred_delete_tx.unbounded_send(());
                                    continue;
                                }
                                _ => {
                                    // Not expired — preserve for the encrypted loop
                                    peeked_message = Some(text.to_string());
                                }
                            }
                        }
                        Ok(Some(Ok(_))) | Ok(None) | Ok(Some(Err(_))) => {
                            // Connection closed or unexpected frame — will be caught in encrypted loop
                        }
                        Err(_) => {
                            // Timeout — no pairing.expired, reconnect is OK
                        }
                    }

                    let _ = status_tx.send(PairingStatus::Paired {
                        pairing_id: keys.pairing_id.clone(),
                        peer_online: false,
                    });
                }

                // Phase 3: Encrypted message loop
                let keys = session_keys.as_mut().unwrap();
                let start = std::time::Instant::now();
                run_encrypted_loop(
                    keys,
                    &mut ws_sink,
                    &mut ws_source,
                    peeked_message,
                    &mut event_rx,
                    &mut command_tx,
                    &status_tx,
                    &peer_connected_tx,
                )
                .await;

                log::info!("zrc: disconnected from relay");

                // If the connection dropped very quickly, the stored pairing
                // is likely invalid. Clear it so we do a fresh pairing next time.
                if start.elapsed().as_secs() < 5 {
                    log::warn!("zrc: connection dropped quickly — clearing stored credentials for re-pairing");
                    session_keys = None;
                    reconnect_token = None;
                    let _ = cred_delete_tx.unbounded_send(());
                }
            }
            Err(e) => {
                log::warn!("zrc: failed to connect to relay: {e}");
                let _ = status_tx.send(PairingStatus::Failed {
                    reason: e.to_string(),
                });
            }
        }

        let _ = status_tx.send(PairingStatus::Disconnected);
        tokio::time::sleep(std::time::Duration::from_secs(3)).await;
    }
}

/// Run the pairing ceremony. Returns (SessionKeys, reconnect_token) on success.
async fn run_pairing<S, R>(
    ws_sink: &mut S,
    ws_source: &mut R,
    status_tx: &watch::Sender<PairingStatus>,
) -> Result<(SessionKeys, Option<String>)>
where
    S: futures::Sink<Message, Error = tokio_tungstenite::tungstenite::Error> + Unpin,
    R: futures::Stream<Item = Result<Message, tokio_tungstenite::tungstenite::Error>> + Unpin,
{
    // 1. Send PairingInit
    send_json(ws_sink, &PairingInit::default()).await?;

    // 2. Wait for PairingInitResult
    let (pairing_id, join_code, init_reconnect_token) = loop {
        match recv_relay_message(ws_source).await? {
            RelayMessage::PairingInitResult(result) => {
                break (result.pairing_id, result.join_code, result.reconnect_token);
            }
            _ => {}
        }
    };
    log::info!("zrc: join code = {join_code}, pairing_id = {pairing_id}");
    let _ = status_tx.send(PairingStatus::WaitingForMobile {
        join_code: join_code.clone(),
    });

    // 3. Generate our keypair
    let keypair = KeyPair::generate();

    // 4. Wait for mobile's PairingKeyExchange, then send ours and derive keys
    let (symmetric_key, sas_code) = loop {
        match recv_relay_message(ws_source).await? {
            RelayMessage::PairingKeyExchange(kx) => {
                let _ = status_tx.send(PairingStatus::KeyExchange);

                let their_pk_bytes = B64
                    .decode(&kx.public_key)
                    .map_err(|e| anyhow::anyhow!("invalid public key base64: {e}"))?;
                if their_pk_bytes.len() != 32 {
                    return Err(anyhow::anyhow!(
                        "invalid public key length: {}",
                        their_pk_bytes.len()
                    ));
                }
                let mut pk_arr = [0u8; 32];
                pk_arr.copy_from_slice(&their_pk_bytes);
                let their_pk = PublicKey::from(pk_arr);

                let shared = keypair.diffie_hellman(&their_pk);
                let sym_key = crypto::derive_symmetric_key(&shared);
                let sas = crypto::derive_sas_code(&shared);

                // Send our public key
                send_json(
                    ws_sink,
                    &PairingKeyExchange::new(&pairing_id, &keypair.public_key_base64()),
                )
                .await?;

                break (sym_key, sas);
            }
            RelayMessage::PeerConnected(_) => {
                log::info!("zrc: mobile connected, waiting for key exchange");
            }
            RelayMessage::PairingReject(reject) => {
                return Err(anyhow::anyhow!("pairing rejected: {}", reject.reason));
            }
            _ => {}
        }
    };

    // 5. Display SAS code and send confirm
    log::info!("zrc: SAS verification code: {sas_code}");
    let _ = status_tx.send(PairingStatus::VerifySas {
        sas_code: sas_code.clone(),
    });

    // Auto-confirm for now (later: wait for user confirmation via UI)
    send_json(ws_sink, &PairingConfirm::new(&pairing_id)).await?;

    // 6. Wait for PairingComplete
    loop {
        match recv_relay_message(ws_source).await? {
            RelayMessage::PairingComplete(_) => {
                log::info!("zrc: pairing complete! pairing_id={pairing_id}");
                return Ok((SessionKeys::new(pairing_id, symmetric_key), init_reconnect_token));
            }
            RelayMessage::PairingReject(reject) => {
                return Err(anyhow::anyhow!("pairing rejected: {}", reject.reason));
            }
            _ => {}
        }
    }
}

/// Main loop after pairing: encrypt outbound TapEvents, decrypt inbound.
async fn run_encrypted_loop<S, R>(
    keys: &mut SessionKeys,
    ws_sink: &mut S,
    ws_source: &mut R,
    first_message: Option<String>,
    event_rx: &mut mpsc::UnboundedReceiver<TapEvent>,
    command_tx: &mut mpsc::UnboundedSender<RelayCommand>,
    status_tx: &watch::Sender<PairingStatus>,
    peer_connected_tx: &mpsc::UnboundedSender<()>,
) where
    S: futures::Sink<Message, Error = tokio_tungstenite::tungstenite::Error> + Unpin,
    R: futures::Stream<Item = Result<Message, tokio_tungstenite::tungstenite::Error>> + Unpin,
{
    let _ = status_tx.send(PairingStatus::Paired {
        pairing_id: keys.pairing_id.clone(),
        peer_online: false,
    });

    // Process any message that was peeked during reconnect
    if let Some(text) = first_message {
        if handle_inbound_text(&text, keys, command_tx, status_tx, peer_connected_tx)
            .await
            .is_err()
        {
            return;
        }
    }

    loop {
        tokio::select! {
            msg = recv_text(ws_source) => {
                match msg {
                    Ok(Some(text)) => {
                        if handle_inbound_text(&text, keys, command_tx, status_tx, peer_connected_tx).await.is_err() {
                            return;
                        }
                    }
                    Ok(None) => break,
                    Err(_) => break,
                }
            }
            event = event_rx.next() => {
                match event {
                    Some(event) => {
                        match serde_json::to_string(&event) {
                            Ok(plaintext) => {
                                let seq = keys.next_sequence();
                                let aad = crypto::build_aad(&keys.pairing_id, "zed", seq);
                                match crypto::encrypt(&plaintext, &keys.symmetric_key, &aad) {
                                    Ok((nonce, ciphertext)) => {
                                        let envelope = EncryptedEnvelope::new(
                                            &keys.pairing_id,
                                            seq,
                                            "zed",
                                            &nonce,
                                            &ciphertext,
                                        );
                                        if send_json(ws_sink, &envelope).await.is_err() {
                                            break;
                                        }
                                    }
                                    Err(e) => {
                                        log::warn!("zrc: encryption failed: {e}");
                                    }
                                }
                            }
                            Err(e) => {
                                log::warn!("zrc: failed to serialize tap event: {e}");
                            }
                        }
                    }
                    None => return,
                }
            }
        }
    }
}

/// Handle a single inbound text message from the relay.
/// Returns Err(()) if the command channel is closed and the loop should exit.
async fn handle_inbound_text(
    text: &str,
    keys: &mut SessionKeys,
    command_tx: &mut mpsc::UnboundedSender<RelayCommand>,
    status_tx: &watch::Sender<PairingStatus>,
    peer_connected_tx: &mpsc::UnboundedSender<()>,
) -> Result<(), ()> {
    match RelayMessage::parse(text) {
        Ok(RelayMessage::Encrypted(env)) => {
            let aad = crypto::build_aad(&env.pairing_id, &env.sender, env.sequence);
            match crypto::decrypt(&env.nonce, &env.ciphertext, &keys.symmetric_key, &aad) {
                Ok(plaintext) => {
                    match serde_json::from_str::<RelayCommand>(&plaintext) {
                        Ok(cmd) => {
                            if command_tx.send(cmd).await.is_err() {
                                return Err(());
                            }
                        }
                        Err(e) => {
                            log::warn!("zrc: failed to parse decrypted command: {e}");
                        }
                    }
                }
                Err(e) => {
                    log::warn!("zrc: decryption failed: {e}");
                }
            }
        }
        Ok(RelayMessage::PeerConnected(pc)) => {
            log::info!("zrc: peer connected: {}", pc.peer_type);
            let _ = status_tx.send(PairingStatus::Paired {
                pairing_id: keys.pairing_id.clone(),
                peer_online: true,
            });
            // Signal tap layer to resync thread state
            let _ = peer_connected_tx.unbounded_send(());
        }
        Ok(RelayMessage::PeerDisconnected(pd)) => {
            log::info!("zrc: peer disconnected: {}", pd.peer_type);
            let _ = status_tx.send(PairingStatus::Paired {
                pairing_id: keys.pairing_id.clone(),
                peer_online: false,
            });
        }
        Ok(RelayMessage::ReplayResponse(rr)) => {
            log::info!("zrc: replay response with {} messages", rr.messages.len());
            for msg_val in &rr.messages {
                if let Ok(env) = serde_json::from_value::<EncryptedEnvelope>(msg_val.clone()) {
                    let aad = crypto::build_aad(&env.pairing_id, &env.sender, env.sequence);
                    if let Ok(pt) =
                        crypto::decrypt(&env.nonce, &env.ciphertext, &keys.symmetric_key, &aad)
                    {
                        if let Ok(cmd) = serde_json::from_str::<RelayCommand>(&pt) {
                            if command_tx.send(cmd).await.is_err() {
                                return Err(());
                            }
                        }
                    }
                }
            }
        }
        Ok(other) => {
            log::debug!("zrc: ignoring relay message: {other:?}");
        }
        Err(e) => {
            log::warn!("zrc: failed to parse relay message: {e}");
        }
    }
    Ok(())
}

// ── Helpers ─────────────────────────────────────────────────────────────────

async fn send_json<S, T: serde::Serialize>(ws_sink: &mut S, msg: &T) -> Result<()>
where
    S: futures::Sink<Message, Error = tokio_tungstenite::tungstenite::Error> + Unpin,
{
    let json = serde_json::to_string(msg)?;
    ws_sink
        .send(Message::Text(json.into()))
        .await
        .map_err(|e| anyhow::anyhow!("WebSocket send failed: {e}"))
}

async fn recv_text<R>(ws_source: &mut R) -> Result<Option<String>>
where
    R: futures::Stream<Item = Result<Message, tokio_tungstenite::tungstenite::Error>> + Unpin,
{
    match ws_source.next().await {
        Some(Ok(Message::Text(text))) => Ok(Some(text.to_string())),
        Some(Ok(Message::Close(_))) | None => Ok(None),
        Some(Err(e)) => {
            log::warn!("zrc: WebSocket read error: {e}");
            Ok(None)
        }
        _ => Ok(None), // Ignore ping/pong/binary
    }
}

async fn recv_relay_message<R>(ws_source: &mut R) -> Result<RelayMessage>
where
    R: futures::Stream<Item = Result<Message, tokio_tungstenite::tungstenite::Error>> + Unpin,
{
    loop {
        match recv_text(ws_source).await? {
            Some(text) => {
                return RelayMessage::parse(&text)
                    .map_err(|e| anyhow::anyhow!("failed to parse relay message: {e}"));
            }
            None => {
                return Err(anyhow::anyhow!("WebSocket connection closed"));
            }
        }
    }
}
