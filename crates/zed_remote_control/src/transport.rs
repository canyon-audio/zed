use crate::protocol::{RelayCommand, TapEvent};
use anyhow::Result;
use futures::channel::mpsc;
use futures::{SinkExt, StreamExt};
use gpui::AppContext;
use gpui_tokio::Tokio;
use tokio_tungstenite::{connect_async, tungstenite::Message};

/// Manages the WebSocket connection to the ZRC relay server.
pub struct RelayTransport {
    /// Send tap events to the relay.
    pub event_tx: mpsc::UnboundedSender<TapEvent>,
    /// Receive commands from the relay.
    pub command_rx: mpsc::UnboundedReceiver<RelayCommand>,
}

impl RelayTransport {
    /// Connect to the relay server and spawn read/write loops.
    ///
    /// Returns a `RelayTransport` with channels for sending events and
    /// receiving commands. The WebSocket I/O runs on the tokio runtime.
    pub fn connect(url: &str, cx: &impl AppContext) -> Result<Self> {
        let (event_tx, event_rx) = mpsc::unbounded::<TapEvent>();
        let (command_tx, command_rx) = mpsc::unbounded::<RelayCommand>();

        let url = url.to_string();
        Tokio::spawn(cx, Self::run_connection_loop(url, event_rx, command_tx))
            .detach();

        Ok(Self {
            event_tx,
            command_rx,
        })
    }

    async fn run_connection_loop(
        url: String,
        mut event_rx: mpsc::UnboundedReceiver<TapEvent>,
        mut command_tx: mpsc::UnboundedSender<RelayCommand>,
    ) {
        loop {
            log::info!("zrc: connecting to relay at {url}");
            match connect_async(&url).await {
                Ok((ws_stream, _)) => {
                    log::info!("zrc: connected to relay");
                    let (mut ws_sink, mut ws_source) = ws_stream.split();

                    loop {
                        tokio::select! {
                            // Read from relay -> send commands to Zed
                            msg = ws_source.next() => {
                                match msg {
                                    Some(Ok(Message::Text(text))) => {
                                        match serde_json::from_str::<RelayCommand>(&text) {
                                            Ok(cmd) => {
                                                if command_tx.send(cmd).await.is_err() {
                                                    return; // command channel closed
                                                }
                                            }
                                            Err(e) => {
                                                log::warn!("zrc: failed to parse relay command: {e}");
                                            }
                                        }
                                    }
                                    Some(Ok(Message::Close(_))) | None => break,
                                    Some(Err(e)) => {
                                        log::warn!("zrc: WebSocket read error: {e}");
                                        break;
                                    }
                                    _ => {}
                                }
                            }
                            // Read tap events from Zed -> send to relay
                            event = event_rx.next() => {
                                match event {
                                    Some(event) => {
                                        match serde_json::to_string(&event) {
                                            Ok(json) => {
                                                if ws_sink.send(Message::Text(json.into())).await.is_err() {
                                                    break;
                                                }
                                            }
                                            Err(e) => {
                                                log::warn!("zrc: failed to serialize tap event: {e}");
                                            }
                                        }
                                    }
                                    None => return, // event channel closed
                                }
                            }
                        }
                    }

                    log::info!("zrc: disconnected from relay");
                }
                Err(e) => {
                    log::warn!("zrc: failed to connect to relay: {e}");
                }
            }

            // Reconnect after delay
            tokio::time::sleep(std::time::Duration::from_secs(3)).await;
        }
    }
}
