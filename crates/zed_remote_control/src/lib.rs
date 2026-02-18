mod protocol;
mod tap;
mod transport;

use gpui::App;

pub fn init(cx: &mut App) {
    tap::init(cx);
}
