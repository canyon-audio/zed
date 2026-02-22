use crate::transport::PairingStatus;
use futures::channel::mpsc;
use futures::StreamExt;
use gpui::{Context, Render, WeakEntity, Window};
use workspace::{StatusItemView, item::ItemHandle, ui::prelude::*};

pub struct ZrcStatusItem {
    status: PairingStatus,
    _task: gpui::Task<()>,
}

impl ZrcStatusItem {
    pub fn new(
        mut status_rx: mpsc::UnboundedReceiver<PairingStatus>,
        cx: &mut Context<Self>,
    ) -> Self {
        let task = cx.spawn(async move |this: WeakEntity<Self>, mut cx| {
            while let Some(status) = status_rx.next().await {
                if this
                    .update(cx, |this, cx| {
                        this.status = status;
                        cx.notify();
                    })
                    .is_err()
                {
                    break;
                }
            }
        });
        Self {
            status: PairingStatus::Disconnected,
            _task: task,
        }
    }
}

impl Render for ZrcStatusItem {
    fn render(&mut self, _window: &mut Window, _cx: &mut Context<Self>) -> impl IntoElement {
        let (text, color) = match &self.status {
            PairingStatus::Disconnected => return div().into_any_element(),
            PairingStatus::Connecting => ("ZRC: ...".into(), Color::Muted),
            PairingStatus::WaitingForMobile { join_code } => {
                (format!("ZRC: {join_code}"), Color::Accent)
            }
            PairingStatus::KeyExchange => ("ZRC: pairing...".into(), Color::Warning),
            PairingStatus::VerifySas { sas_code } => {
                (format!("ZRC: SAS {sas_code}"), Color::Warning)
            }
            PairingStatus::Paired { peer_online: true, .. } => {
                ("ZRC: connected".into(), Color::Success)
            }
            PairingStatus::Paired { peer_online: false, .. } => {
                ("ZRC: paired".into(), Color::Muted)
            }
            PairingStatus::Failed { .. } => ("ZRC: error".into(), Color::Error),
        };

        div()
            .child(
                Label::new(text)
                    .size(LabelSize::Small)
                    .color(color),
            )
            .into_any_element()
    }
}

impl StatusItemView for ZrcStatusItem {
    fn set_active_pane_item(
        &mut self,
        _active_pane_item: Option<&dyn ItemHandle>,
        _window: &mut Window,
        _cx: &mut Context<Self>,
    ) {
    }
}
