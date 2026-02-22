use serde::{Deserialize, Serialize};

// ── Endpoint Protocol (plaintext inside encrypted envelopes) ────────────────

/// Events sent from Zed to the relay server (tap output).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum TapEvent {
    /// A new project/thread became active.
    #[serde(rename = "thread.opened")]
    ThreadOpened {
        project: String,
        thread_id: String,
    },

    /// A thread was closed/deactivated.
    #[serde(rename = "thread.closed")]
    ThreadClosed {
        project: String,
        thread_id: String,
    },

    /// List of all active projects.
    #[serde(rename = "projects.list")]
    ProjectsList { projects: Vec<String> },

    /// A new entry was added to a thread.
    #[serde(rename = "entry.new")]
    EntryNew {
        project: String,
        thread_id: String,
        index: usize,
        entry: EntryData,
    },

    /// An existing entry was updated (e.g., streaming text append).
    #[serde(rename = "entry.updated")]
    EntryUpdated {
        project: String,
        thread_id: String,
        index: usize,
        entry: EntryData,
    },

    /// The agent turn completed.
    #[serde(rename = "thread.stopped")]
    ThreadStopped {
        project: String,
        thread_id: String,
    },

    /// Thread title changed.
    #[serde(rename = "thread.title_changed")]
    TitleChanged {
        project: String,
        thread_id: String,
        title: String,
    },

    /// Token usage update.
    #[serde(rename = "thread.token_usage")]
    TokenUsage {
        project: String,
        thread_id: String,
        input_tokens: Option<u64>,
        output_tokens: Option<u64>,
    },
}

/// Serializable representation of a thread entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind")]
pub enum EntryData {
    #[serde(rename = "user_message")]
    UserMessage { text: String },

    #[serde(rename = "assistant_message")]
    AssistantMessage { text: String, has_thinking: bool },

    #[serde(rename = "tool_call")]
    ToolCall {
        tool_name: Option<String>,
        status: String,
        input: Option<serde_json::Value>,
        output: Option<serde_json::Value>,
    },
}

/// Messages sent from the relay server to Zed (inbound commands).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum RelayCommand {
    /// Send a prompt to a specific project's active thread.
    #[serde(rename = "prompt")]
    Prompt { project: String, text: String },
}

// ── Relay Envelope Protocol (control plane + encrypted data plane) ──────────

/// Client handshake sent immediately after WebSocket connect.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClientHandshake {
    #[serde(rename = "type")]
    pub msg_type: String,
    pub client_type: String,
    pub client_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pairing_id: Option<String>,
}

impl ClientHandshake {
    pub fn new_zed(client_id: &str, pairing_id: Option<&str>) -> Self {
        Self {
            msg_type: "handshake".into(),
            client_type: "zed".into(),
            client_id: client_id.into(),
            pairing_id: pairing_id.map(Into::into),
        }
    }
}

/// Zed requests a new pairing session.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PairingInit {
    #[serde(rename = "type")]
    pub msg_type: String,
}

impl Default for PairingInit {
    fn default() -> Self {
        Self {
            msg_type: "pairing.init".into(),
        }
    }
}

/// Relay responds with join code and pairing ID.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PairingInitResult {
    #[serde(rename = "type")]
    pub msg_type: String,
    pub pairing_id: String,
    pub join_code: String,
}

/// Both sides send their X25519 public key via the relay.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PairingKeyExchange {
    #[serde(rename = "type")]
    pub msg_type: String,
    pub pairing_id: String,
    pub public_key: String,
}

impl PairingKeyExchange {
    pub fn new(pairing_id: &str, public_key_b64: &str) -> Self {
        Self {
            msg_type: "pairing.key_exchange".into(),
            pairing_id: pairing_id.into(),
            public_key: public_key_b64.into(),
        }
    }
}

/// User confirmed the SAS codes match.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PairingConfirm {
    #[serde(rename = "type")]
    pub msg_type: String,
    pub pairing_id: String,
}

impl PairingConfirm {
    pub fn new(pairing_id: &str) -> Self {
        Self {
            msg_type: "pairing.confirm".into(),
            pairing_id: pairing_id.into(),
        }
    }
}

/// Relay notifies both sides that pairing succeeded.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PairingComplete {
    #[serde(rename = "type")]
    pub msg_type: String,
    pub pairing_id: String,
}

/// Either side rejects the pairing (SAS mismatch or user cancelled).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PairingReject {
    #[serde(rename = "type")]
    pub msg_type: String,
    pub pairing_id: String,
    #[serde(default)]
    pub reason: String,
}

/// Relay notifies that a peer connected.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerConnected {
    #[serde(rename = "type")]
    pub msg_type: String,
    pub pairing_id: String,
    pub peer_type: String,
}

/// Relay notifies that a peer disconnected.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerDisconnected {
    #[serde(rename = "type")]
    pub msg_type: String,
    pub pairing_id: String,
    pub peer_type: String,
}

/// Opaque encrypted message. Relay routes by pairing_id but cannot read payload.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptedEnvelope {
    #[serde(rename = "type")]
    pub msg_type: String,
    pub pairing_id: String,
    pub sequence: u64,
    pub sender: String,
    pub nonce: String,
    pub ciphertext: String,
    pub timestamp: String,
}

impl EncryptedEnvelope {
    pub fn new(
        pairing_id: &str,
        sequence: u64,
        sender: &str,
        nonce: &str,
        ciphertext: &str,
    ) -> Self {
        Self {
            msg_type: "encrypted".into(),
            pairing_id: pairing_id.into(),
            sequence,
            sender: sender.into(),
            nonce: nonce.into(),
            ciphertext: ciphertext.into(),
            timestamp: chrono::Utc::now().format("%Y-%m-%dT%H:%M:%SZ").to_string(),
        }
    }
}

/// Client requests missed messages since a given sequence number.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReplayRequest {
    #[serde(rename = "type")]
    pub msg_type: String,
    pub pairing_id: String,
    #[serde(default)]
    pub since_sequence: u64,
}

impl ReplayRequest {
    pub fn new(pairing_id: &str, since_sequence: u64) -> Self {
        Self {
            msg_type: "replay.request".into(),
            pairing_id: pairing_id.into(),
            since_sequence,
        }
    }
}

/// Relay sends stored encrypted messages for offline replay.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReplayResponse {
    #[serde(rename = "type")]
    pub msg_type: String,
    pub pairing_id: String,
    pub messages: Vec<serde_json::Value>,
    #[serde(default)]
    pub has_more: bool,
}

// ── Relay Message Dispatch ──────────────────────────────────────────────────

/// Incoming relay message, discriminated by "type" field.
#[derive(Debug, Clone)]
pub enum RelayMessage {
    PairingInitResult(PairingInitResult),
    PairingKeyExchange(PairingKeyExchange),
    PairingComplete(PairingComplete),
    PairingReject(PairingReject),
    PeerConnected(PeerConnected),
    PeerDisconnected(PeerDisconnected),
    Encrypted(EncryptedEnvelope),
    ReplayResponse(ReplayResponse),
    Unknown(String),
}

impl RelayMessage {
    pub fn parse(text: &str) -> Result<Self, serde_json::Error> {
        let v: serde_json::Value = serde_json::from_str(text)?;
        let msg_type = v.get("type").and_then(|t| t.as_str()).unwrap_or("");
        match msg_type {
            "pairing.init_result" => Ok(Self::PairingInitResult(serde_json::from_value(v)?)),
            "pairing.key_exchange" => Ok(Self::PairingKeyExchange(serde_json::from_value(v)?)),
            "pairing.complete" => Ok(Self::PairingComplete(serde_json::from_value(v)?)),
            "pairing.reject" => Ok(Self::PairingReject(serde_json::from_value(v)?)),
            "peer.connected" => Ok(Self::PeerConnected(serde_json::from_value(v)?)),
            "peer.disconnected" => Ok(Self::PeerDisconnected(serde_json::from_value(v)?)),
            "encrypted" => Ok(Self::Encrypted(serde_json::from_value(v)?)),
            "replay.response" => Ok(Self::ReplayResponse(serde_json::from_value(v)?)),
            other => Ok(Self::Unknown(other.to_string())),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── Endpoint Protocol Tests ─────────────────────────────────────────

    #[test]
    fn test_tap_event_thread_opened_roundtrip() {
        let event = TapEvent::ThreadOpened {
            project: "myproj".into(),
            thread_id: "t1".into(),
        };
        let json = serde_json::to_string(&event).unwrap();
        assert!(json.contains(r#""type":"thread.opened""#));
        let parsed: TapEvent = serde_json::from_str(&json).unwrap();
        match parsed {
            TapEvent::ThreadOpened {
                project,
                thread_id,
            } => {
                assert_eq!(project, "myproj");
                assert_eq!(thread_id, "t1");
            }
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn test_tap_event_entry_new_roundtrip() {
        let event = TapEvent::EntryNew {
            project: "p".into(),
            thread_id: "t".into(),
            index: 0,
            entry: EntryData::UserMessage {
                text: "hello".into(),
            },
        };
        let json = serde_json::to_string(&event).unwrap();
        assert!(json.contains(r#""type":"entry.new""#));
        assert!(json.contains(r#""kind":"user_message""#));
        let parsed: TapEvent = serde_json::from_str(&json).unwrap();
        match parsed {
            TapEvent::EntryNew { entry, .. } => match entry {
                EntryData::UserMessage { text } => assert_eq!(text, "hello"),
                _ => panic!("wrong entry kind"),
            },
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn test_relay_command_prompt_roundtrip() {
        let cmd = RelayCommand::Prompt {
            project: "myproj".into(),
            text: "do something".into(),
        };
        let json = serde_json::to_string(&cmd).unwrap();
        assert!(json.contains(r#""type":"prompt""#));
        let parsed: RelayCommand = serde_json::from_str(&json).unwrap();
        match parsed {
            RelayCommand::Prompt { project, text } => {
                assert_eq!(project, "myproj");
                assert_eq!(text, "do something");
            }
        }
    }

    // ── Relay Envelope Tests ────────────────────────────────────────────

    #[test]
    fn test_serialize_client_handshake() {
        let hs = ClientHandshake::new_zed("client-123", None);
        let json = serde_json::to_string(&hs).unwrap();
        assert!(json.contains(r#""type":"handshake""#));
        assert!(json.contains(r#""client_type":"zed""#));
        assert!(json.contains(r#""client_id":"client-123""#));
        assert!(!json.contains("pairing_id"));
    }

    #[test]
    fn test_serialize_client_handshake_with_pairing_id() {
        let hs = ClientHandshake::new_zed("client-123", Some("pid-456"));
        let json = serde_json::to_string(&hs).unwrap();
        assert!(json.contains(r#""pairing_id":"pid-456""#));
    }

    #[test]
    fn test_serialize_pairing_init() {
        let init = PairingInit::default();
        let json = serde_json::to_string(&init).unwrap();
        assert_eq!(json, r#"{"type":"pairing.init"}"#);
    }

    #[test]
    fn test_parse_pairing_init_result() {
        let json = r#"{"type":"pairing.init_result","pairing_id":"pid-1","join_code":"ABC123"}"#;
        let msg = RelayMessage::parse(json).unwrap();
        match msg {
            RelayMessage::PairingInitResult(r) => {
                assert_eq!(r.pairing_id, "pid-1");
                assert_eq!(r.join_code, "ABC123");
            }
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn test_parse_pairing_key_exchange() {
        let json = r#"{"type":"pairing.key_exchange","pairing_id":"pid-1","public_key":"AAAA"}"#;
        let msg = RelayMessage::parse(json).unwrap();
        match msg {
            RelayMessage::PairingKeyExchange(kx) => {
                assert_eq!(kx.pairing_id, "pid-1");
                assert_eq!(kx.public_key, "AAAA");
            }
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn test_serialize_pairing_key_exchange() {
        let kx = PairingKeyExchange::new("pid-1", "BASE64KEY==");
        let json = serde_json::to_string(&kx).unwrap();
        assert!(json.contains(r#""type":"pairing.key_exchange""#));
        assert!(json.contains(r#""public_key":"BASE64KEY==""#));
    }

    #[test]
    fn test_serialize_pairing_confirm() {
        let c = PairingConfirm::new("pid-1");
        let json = serde_json::to_string(&c).unwrap();
        assert!(json.contains(r#""type":"pairing.confirm""#));
        assert!(json.contains(r#""pairing_id":"pid-1""#));
    }

    #[test]
    fn test_parse_pairing_complete() {
        let json = r#"{"type":"pairing.complete","pairing_id":"pid-1"}"#;
        let msg = RelayMessage::parse(json).unwrap();
        match msg {
            RelayMessage::PairingComplete(c) => {
                assert_eq!(c.pairing_id, "pid-1");
            }
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn test_parse_pairing_reject() {
        let json = r#"{"type":"pairing.reject","pairing_id":"pid-1","reason":"SAS mismatch"}"#;
        let msg = RelayMessage::parse(json).unwrap();
        match msg {
            RelayMessage::PairingReject(r) => {
                assert_eq!(r.pairing_id, "pid-1");
                assert_eq!(r.reason, "SAS mismatch");
            }
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn test_parse_peer_connected() {
        let json = r#"{"type":"peer.connected","pairing_id":"pid-1","peer_type":"mobile"}"#;
        let msg = RelayMessage::parse(json).unwrap();
        match msg {
            RelayMessage::PeerConnected(pc) => {
                assert_eq!(pc.pairing_id, "pid-1");
                assert_eq!(pc.peer_type, "mobile");
            }
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn test_parse_peer_disconnected() {
        let json = r#"{"type":"peer.disconnected","pairing_id":"pid-1","peer_type":"zed"}"#;
        let msg = RelayMessage::parse(json).unwrap();
        match msg {
            RelayMessage::PeerDisconnected(pd) => {
                assert_eq!(pd.pairing_id, "pid-1");
                assert_eq!(pd.peer_type, "zed");
            }
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn test_parse_encrypted_envelope() {
        let json = r#"{"type":"encrypted","pairing_id":"pid-1","sequence":5,"sender":"mobile","nonce":"abc=","ciphertext":"xyz=","timestamp":"2026-01-01T00:00:00Z"}"#;
        let msg = RelayMessage::parse(json).unwrap();
        match msg {
            RelayMessage::Encrypted(env) => {
                assert_eq!(env.pairing_id, "pid-1");
                assert_eq!(env.sequence, 5);
                assert_eq!(env.sender, "mobile");
                assert_eq!(env.nonce, "abc=");
                assert_eq!(env.ciphertext, "xyz=");
            }
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn test_serialize_encrypted_envelope() {
        let env = EncryptedEnvelope::new("pid-1", 1, "zed", "nonce_b64", "ct_b64");
        let json = serde_json::to_string(&env).unwrap();
        assert!(json.contains(r#""type":"encrypted""#));
        assert!(json.contains(r#""sender":"zed""#));
        assert!(json.contains(r#""sequence":1"#));
    }

    #[test]
    fn test_parse_replay_response() {
        let json = r#"{"type":"replay.response","pairing_id":"pid-1","messages":[{"type":"encrypted","sequence":1}],"has_more":false}"#;
        let msg = RelayMessage::parse(json).unwrap();
        match msg {
            RelayMessage::ReplayResponse(rr) => {
                assert_eq!(rr.pairing_id, "pid-1");
                assert_eq!(rr.messages.len(), 1);
                assert!(!rr.has_more);
            }
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn test_serialize_replay_request() {
        let rr = ReplayRequest::new("pid-1", 42);
        let json = serde_json::to_string(&rr).unwrap();
        assert!(json.contains(r#""type":"replay.request""#));
        assert!(json.contains(r#""since_sequence":42"#));
    }

    #[test]
    fn test_parse_unknown_type() {
        let json = r#"{"type":"some.future.message","data":123}"#;
        let msg = RelayMessage::parse(json).unwrap();
        match msg {
            RelayMessage::Unknown(t) => assert_eq!(t, "some.future.message"),
            _ => panic!("should be Unknown"),
        }
    }

    #[test]
    fn test_parse_missing_type() {
        let json = r#"{"data":123}"#;
        let msg = RelayMessage::parse(json).unwrap();
        match msg {
            RelayMessage::Unknown(t) => assert_eq!(t, ""),
            _ => panic!("should be Unknown"),
        }
    }
}
