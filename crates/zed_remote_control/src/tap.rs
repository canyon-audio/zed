use crate::protocol::{EntryData, RelayCommand, TapEvent};
use crate::transport::RelayTransport;
use acp_thread::{AcpThread, AcpThreadEvent, AgentThreadEntry, AssistantMessageChunk};
use agent_ui::{AgentPanel, AgentPanelEvent};
use futures::channel::mpsc;
use futures::StreamExt;
use gpui::{App, AsyncApp, Context, Entity, Global, Subscription};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use workspace::Workspace;

const DEFAULT_RELAY_URL: &str = "ws://127.0.0.1:9090";

struct ZrcTapGlobal {
    _event_tx: mpsc::UnboundedSender<TapEvent>,
}

impl Global for ZrcTapGlobal {}

pub fn init(cx: &mut App) {
    let relay_url =
        std::env::var("ZRC_RELAY_URL").unwrap_or_else(|_| DEFAULT_RELAY_URL.to_string());

    match RelayTransport::connect(&relay_url, cx) {
        Ok(transport) => {
            log::info!("zrc: tap initialized, connecting to {relay_url}");

            let event_tx = transport.event_tx.clone();
            cx.set_global(ZrcTapGlobal {
                _event_tx: transport.event_tx,
            });

            // Handle inbound commands from relay
            spawn_inbound_handler(transport.command_rx, cx);

            // Observe all new Workspace instances to find AgentPanels
            cx.observe_new::<Workspace>(move |workspace, _window, cx| {
                let event_tx = event_tx.clone();
                setup_workspace_tap(workspace, event_tx, cx);
            })
            .detach();
        }
        Err(e) => {
            log::warn!("zrc: failed to initialize tap: {e}");
        }
    }
}

/// Set up tapping for a workspace.
fn setup_workspace_tap(
    workspace: &mut Workspace,
    event_tx: mpsc::UnboundedSender<TapEvent>,
    cx: &mut Context<Workspace>,
) {
    let tracked = Arc::new(Mutex::new(TrackedState::default()));

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

fn spawn_inbound_handler(mut command_rx: mpsc::UnboundedReceiver<RelayCommand>, cx: &App) {
    cx.spawn(async move |_cx: &mut AsyncApp| {
        while let Some(cmd) = command_rx.next().await {
            match cmd {
                RelayCommand::Prompt { project, text } => {
                    log::info!("zrc: received prompt for project {project}: {text}");
                    inject_prompt(&project, &text);
                }
            }
        }
    })
    .detach();
}

fn inject_prompt(project_name: &str, text: &str) {
    // TODO: Find the workspace with a matching project, get its AgentPanel,
    // get the active AcpThread, and call thread.send() to inject the prompt.
    log::info!(
        "zrc: inject_prompt for {project_name}: {text} (not yet implemented)"
    );
}

#[derive(Default)]
struct TrackedState {
    threads: HashMap<String, TrackedThread>,
}

struct TrackedThread {
    _project_name: String,
    _subscription: Subscription,
}
