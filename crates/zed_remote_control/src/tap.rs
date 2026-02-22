use crate::protocol::{EntryData, RelayCommand, TapEvent};
use crate::status_bar::ZrcStatusItem;
use crate::transport::{PairingStatus, RelayTransport, StoredCredentials};
use acp_thread::{AcpThread, AcpThreadEvent, AgentThreadEntry, AssistantMessageChunk};
use agent_ui::{AgentPanel, AgentPanelEvent};
use base64::{engine::general_purpose::STANDARD as B64, Engine};
use credentials_provider::CredentialsProvider;
use futures::channel::mpsc;
use futures::StreamExt;
use gpui::{App, AppContext, AsyncApp, Context, Entity, Global, Subscription, WeakEntity};
use gpui_tokio::Tokio;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use workspace::Workspace;

const DEFAULT_RELAY_URL: &str = "wss://zrc-relay.fly.dev";
const CREDENTIAL_URL: &str = "zrc://pairing";

struct ZrcTapGlobal {
    _event_tx: mpsc::UnboundedSender<TapEvent>,
    workspaces: Arc<Mutex<Vec<TrackedWorkspace>>>,
    status_rx: Mutex<Option<mpsc::UnboundedReceiver<PairingStatus>>>,
}

impl Global for ZrcTapGlobal {}

struct TrackedWorkspace {
    project_name: String,
    workspace: WeakEntity<Workspace>,
}

pub fn init(cx: &mut App) {
    let relay_url =
        std::env::var("ZRC_RELAY_URL").unwrap_or_else(|_| DEFAULT_RELAY_URL.to_string());

    // Load stored credentials and start transport asynchronously
    let relay_url_clone = relay_url.clone();
    cx.spawn(async move |cx: &mut AsyncApp| {
        // Try to load existing pairing credentials from keychain
        let stored = load_credentials(cx).await;

        cx.update(|cx| {
            start_transport(&relay_url_clone, stored, cx);
        });
    })
    .detach();
}

async fn load_credentials(cx: &AsyncApp) -> Option<StoredCredentials> {
    let provider = cx.update(|cx| <dyn CredentialsProvider>::global(cx));
    let result = provider.read_credentials(CREDENTIAL_URL, cx).await;
    match result {
        Ok(Some((pairing_id, bytes))) => {
            // Try JSON deserialization first (new format with reconnect_token)
            if let Ok(creds) = serde_json::from_slice::<StoredCredentials>(&bytes) {
                log::info!("zrc: loaded stored pairing credentials for {}", creds.pairing_id);
                return Some(creds);
            }
            // Fall back: raw key bytes (old format, no reconnect token)
            log::info!("zrc: loaded stored pairing credentials (legacy format) for {pairing_id}");
            Some(StoredCredentials {
                pairing_id,
                symmetric_key_b64: B64.encode(&bytes),
                reconnect_token: None,
            })
        }
        Ok(None) => {
            log::info!("zrc: no stored pairing credentials found");
            None
        }
        Err(e) => {
            log::warn!("zrc: failed to load credentials: {e}");
            None
        }
    }
}

fn start_transport(relay_url: &str, stored: Option<StoredCredentials>, cx: &mut App) {
    match RelayTransport::connect(relay_url, stored, cx) {
        Ok(transport) => {
            log::info!("zrc: tap initialized, connecting to {relay_url}");

            let event_tx = transport.event_tx.clone();
            let workspaces = Arc::new(Mutex::new(Vec::<TrackedWorkspace>::new()));

            // Bridge tokio watch channel → futures mpsc for GPUI consumption
            let (status_bridge_tx, status_bridge_rx) = mpsc::unbounded::<PairingStatus>();
            let mut status_rx = transport.status_rx;
            Tokio::spawn(cx, async move {
                while status_rx.changed().await.is_ok() {
                    let status = status_rx.borrow().clone();
                    if status_bridge_tx.unbounded_send(status).is_err() {
                        break;
                    }
                }
            })
            .detach();

            cx.set_global(ZrcTapGlobal {
                _event_tx: transport.event_tx,
                workspaces: workspaces.clone(),
                status_rx: Mutex::new(Some(status_bridge_rx)),
            });

            // Handle inbound commands from relay
            spawn_inbound_handler(transport.command_rx, cx);

            // Handle peer reconnect — resync current thread state to mobile
            spawn_resync_handler(transport.peer_connected_rx, event_tx.clone(), cx);

            // Handle credential saves and deletes
            spawn_credential_saver(transport.credential_save_rx, cx);
            spawn_credential_deleter(transport.credential_delete_rx, cx);

            // Observe all new Workspace instances to find AgentPanels
            let workspaces2 = workspaces.clone();
            cx.observe_new::<Workspace>(move |workspace, window, cx| {
                let event_tx = event_tx.clone();
                let workspaces = workspaces2.clone();
                setup_workspace_tap(workspace, event_tx, workspaces, cx);

                // Register status bar item (first workspace only)
                let window = match window {
                    Some(w) => w,
                    None => return,
                };
                if let Some(status_rx) = cx
                    .try_global::<ZrcTapGlobal>()
                    .and_then(|g| g.status_rx.lock().unwrap().take())
                {
                    let item = cx.new(|cx| ZrcStatusItem::new(status_rx, cx));
                    workspace.status_bar().update(cx, |bar, cx| {
                        bar.add_left_item(item, window, cx);
                    });
                }
            })
            .detach();
        }
        Err(e) => {
            log::warn!("zrc: failed to initialize tap: {e}");
        }
    }
}

fn spawn_credential_saver(
    mut cred_rx: mpsc::UnboundedReceiver<StoredCredentials>,
    cx: &App,
) {
    cx.spawn(async move |cx: &mut AsyncApp| {
        while let Some(creds) = cred_rx.next().await {
            let provider = cx.update(|cx| <dyn CredentialsProvider>::global(cx));
            // Serialize the full StoredCredentials as JSON (includes reconnect_token)
            let payload = match serde_json::to_vec(&creds) {
                Ok(p) => p,
                Err(_) => continue,
            };
            match provider
                .write_credentials(CREDENTIAL_URL, &creds.pairing_id, &payload, cx)
                .await
            {
                Ok(()) => {
                    log::info!("zrc: saved pairing credentials for {}", creds.pairing_id);
                }
                Err(e) => {
                    log::warn!("zrc: failed to save credentials: {e}");
                }
            }
        }
    })
    .detach();
}

fn spawn_credential_deleter(
    mut delete_rx: mpsc::UnboundedReceiver<()>,
    cx: &App,
) {
    cx.spawn(async move |cx: &mut AsyncApp| {
        while delete_rx.next().await.is_some() {
            let provider = cx.update(|cx| <dyn CredentialsProvider>::global(cx));
            match provider.delete_credentials(CREDENTIAL_URL, cx).await {
                Ok(()) => {
                    log::info!("zrc: deleted stale pairing credentials from keychain");
                }
                Err(e) => {
                    log::warn!("zrc: failed to delete credentials: {e}");
                }
            }
        }
    })
    .detach();
}

/// Set up tapping for a workspace.
fn setup_workspace_tap(
    workspace: &mut Workspace,
    event_tx: mpsc::UnboundedSender<TapEvent>,
    workspaces: Arc<Mutex<Vec<TrackedWorkspace>>>,
    cx: &mut Context<Workspace>,
) {
    let tracked = Arc::new(Mutex::new(TrackedState::default()));

    // Register this workspace for prompt injection
    let project_name = workspace
        .project()
        .read(cx)
        .visible_worktrees(cx)
        .next()
        .map(|wt| wt.read(cx).root_name_str().to_string())
        .unwrap_or_else(|| "unknown".to_string());

    workspaces.lock().unwrap().push(TrackedWorkspace {
        project_name,
        workspace: cx.entity().downgrade(),
    });

    // If AgentPanel already exists, observe it now
    if let Some(panel) = workspace.panel::<AgentPanel>(cx) {
        observe_agent_panel(&panel, event_tx.clone(), tracked.clone(), cx);
    }

    // Use observe_self to detect when AgentPanel becomes available
    let tracked2 = tracked.clone();
    let event_tx2 = event_tx.clone();
    let mut panel_observed = workspace.panel::<AgentPanel>(cx).is_some();
    cx.observe_self(move |workspace: &mut Workspace, cx: &mut Context<Workspace>| {
        if !panel_observed {
            if let Some(panel) = workspace.panel::<AgentPanel>(cx) {
                panel_observed = true;
                observe_agent_panel(&panel, event_tx2.clone(), tracked2.clone(), cx);
            }
        }
    })
    .detach();
}

/// Subscribe to an AgentPanel's active thread changes.
fn observe_agent_panel(
    panel: &Entity<AgentPanel>,
    event_tx: mpsc::UnboundedSender<TapEvent>,
    tracked: Arc<Mutex<TrackedState>>,
    cx: &mut Context<Workspace>,
) {
    // Tap currently active thread
    if let Some(thread) = panel.read(cx).active_agent_thread(cx) {
        maybe_tap_thread(thread, event_tx.clone(), tracked.clone(), cx);
    }

    // Subscribe to future active view changes
    cx.subscribe(panel, move |_workspace, panel, event: &AgentPanelEvent, cx| {
        match event {
            AgentPanelEvent::ActiveViewChanged => {
                if let Some(thread) = panel.read(cx).active_agent_thread(cx) {
                    maybe_tap_thread(thread.clone(), event_tx.clone(), tracked.clone(), cx);
                }
            }
        }
    })
    .detach();
}

/// Start tapping a thread if we haven't already.
fn maybe_tap_thread(
    thread: Entity<AcpThread>,
    mut event_tx: mpsc::UnboundedSender<TapEvent>,
    tracked: Arc<Mutex<TrackedState>>,
    cx: &mut Context<Workspace>,
) {
    let session_id = thread.read(cx).session_id().to_string();

    {
        let state = tracked.lock().unwrap();
        if state.threads.contains_key(&session_id) {
            return;
        }
    }

    let project = thread.read(cx).project().clone();
    let project_name = project
        .read(cx)
        .visible_worktrees(cx)
        .next()
        .map(|wt| wt.read(cx).root_name_str().to_string())
        .unwrap_or_else(|| "unknown".to_string());

    log::info!("zrc: tapping thread {session_id} for project {project_name}");

    // Send thread.opened
    let _ = event_tx.unbounded_send(TapEvent::ThreadOpened {
        project: project_name.clone(),
        thread_id: session_id.clone(),
    });

    // Replay existing entries
    let entries = thread.read(cx).entries();
    for (idx, entry) in entries.iter().enumerate() {
        let _ = event_tx.unbounded_send(TapEvent::EntryNew {
            project: project_name.clone(),
            thread_id: session_id.clone(),
            index: idx,
            entry: serialize_entry(entry, cx),
        });
    }

    // Subscribe to future events
    let proj = project_name.clone();
    let sid = session_id.clone();
    let sub = cx.subscribe(&thread, move |_workspace, thread, event, cx| {
        handle_thread_event(&thread, event, &proj, &sid, &mut event_tx, cx);
    });

    tracked.lock().unwrap().threads.insert(
        session_id,
        TrackedThread {
            _project_name: project_name,
            _subscription: sub,
        },
    );
}

fn handle_thread_event(
    thread: &Entity<AcpThread>,
    event: &AcpThreadEvent,
    project: &str,
    thread_id: &str,
    event_tx: &mut mpsc::UnboundedSender<TapEvent>,
    cx: &mut Context<Workspace>,
) {
    let thread = thread.read(cx);
    match event {
        AcpThreadEvent::NewEntry => {
            let entries = thread.entries();
            if let Some(entry) = entries.last() {
                let _ = event_tx.unbounded_send(TapEvent::EntryNew {
                    project: project.to_string(),
                    thread_id: thread_id.to_string(),
                    index: entries.len() - 1,
                    entry: serialize_entry(entry, cx),
                });
            }
        }
        AcpThreadEvent::EntryUpdated(idx) => {
            if let Some(entry) = thread.entries().get(*idx) {
                let _ = event_tx.unbounded_send(TapEvent::EntryUpdated {
                    project: project.to_string(),
                    thread_id: thread_id.to_string(),
                    index: *idx,
                    entry: serialize_entry(entry, cx),
                });
            }
        }
        AcpThreadEvent::Stopped => {
            let _ = event_tx.unbounded_send(TapEvent::ThreadStopped {
                project: project.to_string(),
                thread_id: thread_id.to_string(),
            });
        }
        AcpThreadEvent::TitleUpdated => {
            let _ = event_tx.unbounded_send(TapEvent::TitleChanged {
                project: project.to_string(),
                thread_id: thread_id.to_string(),
                title: thread.title().to_string(),
            });
        }
        AcpThreadEvent::TokenUsageUpdated => {
            if let Some(usage) = thread.token_usage() {
                let _ = event_tx.unbounded_send(TapEvent::TokenUsage {
                    project: project.to_string(),
                    thread_id: thread_id.to_string(),
                    input_tokens: Some(usage.input_tokens),
                    output_tokens: Some(usage.output_tokens),
                });
            }
        }
        _ => {}
    }
}

fn serialize_entry(entry: &AgentThreadEntry, cx: &App) -> EntryData {
    match entry {
        AgentThreadEntry::UserMessage(msg) => EntryData::UserMessage {
            text: msg.content.to_markdown(cx).to_string(),
        },
        AgentThreadEntry::AssistantMessage(msg) => {
            let mut text = String::new();
            let mut has_thinking = false;
            for chunk in &msg.chunks {
                match chunk {
                    AssistantMessageChunk::Message { block } => {
                        text.push_str(block.to_markdown(cx));
                    }
                    AssistantMessageChunk::Thought { block } => {
                        has_thinking = true;
                        text.push_str("<thinking>\n");
                        text.push_str(block.to_markdown(cx));
                        text.push_str("\n</thinking>\n");
                    }
                }
            }
            EntryData::AssistantMessage { text, has_thinking }
        }
        AgentThreadEntry::ToolCall(tc) => EntryData::ToolCall {
            tool_name: tc.tool_name.as_ref().map(|s| s.to_string()),
            status: format!("{:?}", tc.status),
            input: tc.raw_input.clone(),
            output: tc.raw_output.clone(),
        },
    }
}

fn spawn_resync_handler(
    mut peer_connected_rx: mpsc::UnboundedReceiver<()>,
    event_tx: mpsc::UnboundedSender<TapEvent>,
    cx: &App,
) {
    cx.spawn(async move |cx: &mut AsyncApp| {
        while peer_connected_rx.next().await.is_some() {
            log::info!("zrc: peer reconnected, resyncing current thread state");
            let mut event_tx = event_tx.clone();
            cx.update(|cx| {
                let workspaces: Option<Vec<TrackedWorkspace>> = cx
                    .try_global::<ZrcTapGlobal>()
                    .map(|g| g.workspaces.lock().unwrap().clone());
                let Some(workspaces) = workspaces else { return };

                for tw in &workspaces {
                    let Some(workspace) = tw.workspace.upgrade() else { continue };
                    let workspace = workspace.read(cx);
                    let Some(panel) = workspace.panel::<AgentPanel>(cx) else { continue };
                    let Some(thread) = panel.read(cx).active_agent_thread(cx) else { continue };

                    let thread = thread.read(cx);
                    let session_id = thread.session_id().to_string();
                    let project_name = tw.project_name.clone();

                    log::info!("zrc: resyncing thread {session_id} ({} entries)", thread.entries().len());

                    let _ = event_tx.unbounded_send(TapEvent::ThreadOpened {
                        project: project_name.clone(),
                        thread_id: session_id.clone(),
                    });

                    for (idx, entry) in thread.entries().iter().enumerate() {
                        let _ = event_tx.unbounded_send(TapEvent::EntryNew {
                            project: project_name.clone(),
                            thread_id: session_id.clone(),
                            index: idx,
                            entry: serialize_entry(entry, cx),
                        });
                    }

                    if !thread.title().is_empty() {
                        let _ = event_tx.unbounded_send(TapEvent::TitleChanged {
                            project: project_name.clone(),
                            thread_id: session_id.clone(),
                            title: thread.title().to_string(),
                        });
                    }
                }
            });
        }
    })
    .detach();
}

fn spawn_inbound_handler(mut command_rx: mpsc::UnboundedReceiver<RelayCommand>, cx: &App) {
    cx.spawn(async move |cx: &mut AsyncApp| {
        while let Some(cmd) = command_rx.next().await {
            match cmd {
                RelayCommand::Prompt { project, text } => {
                    log::info!("zrc: received prompt for project {project}: {text}");
                    inject_prompt(&project, &text, cx);
                }
            }
        }
    })
    .detach();
}

fn inject_prompt(project_name: &str, text: &str, cx: &mut AsyncApp) {
    let workspaces: Option<Vec<TrackedWorkspace>> = cx.update(|cx| {
        cx.try_global::<ZrcTapGlobal>()
            .map(|g| g.workspaces.lock().unwrap().clone())
    });

    let workspaces = match workspaces {
        Some(ws) => ws,
        None => {
            log::warn!("zrc: cannot inject prompt — no ZrcTapGlobal");
            return;
        }
    };

    // Find matching workspace; fall back to first available if project_name is empty
    let target = if project_name.is_empty() {
        workspaces.iter().find(|tw| tw.workspace.upgrade().is_some())
    } else {
        workspaces
            .iter()
            .find(|tw| tw.project_name == project_name)
            .or_else(|| {
                log::warn!(
                    "zrc: no workspace named '{}', falling back to first available",
                    project_name
                );
                workspaces.iter().find(|tw| tw.workspace.upgrade().is_some())
            })
    };

    let Some(tw) = target else {
        log::warn!("zrc: no workspace available for prompt injection");
        return;
    };

    if let Some(workspace) = tw.workspace.upgrade() {
        let text = text.to_string();
        let proj = tw.project_name.clone();
        cx.update(|cx| {
            workspace.update(cx, |workspace, cx| {
                if let Some(panel) = workspace.panel::<AgentPanel>(cx) {
                    if let Some(thread) = panel.read(cx).active_agent_thread(cx) {
                        log::info!("zrc: injecting prompt into thread for {proj}");
                        let content_block: agent_client_protocol::ContentBlock = text.into();
                        thread.update(cx, |thread, cx| {
                            let fut = thread.send(vec![content_block], cx);
                            smol::spawn(async move {
                                if let Err(e) = fut.await {
                                    log::warn!("zrc: failed to inject prompt: {e}");
                                }
                            })
                            .detach();
                        });
                    }
                }
            });
        });
    }
}

#[derive(Default)]
struct TrackedState {
    threads: HashMap<String, TrackedThread>,
}

struct TrackedThread {
    _project_name: String,
    _subscription: Subscription,
}

impl Clone for TrackedWorkspace {
    fn clone(&self) -> Self {
        Self {
            project_name: self.project_name.clone(),
            workspace: self.workspace.clone(),
        }
    }
}
