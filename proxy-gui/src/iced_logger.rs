use std::sync::{Arc, LazyLock};

use futures::stream::unfold;
use iced::Subscription;
use log::{Level, LevelFilter};
use tokio::sync::{
    RwLock,
    mpsc::{self, UnboundedReceiver, UnboundedSender},
};

pub(crate) static GLOBAL_LOGGER: LazyLock<IcedLogger> = LazyLock::new(|| {
    let (sender, receiver) = mpsc::unbounded_channel();
    IcedLogger { sender, receiver: Arc::new(receiver.into()) }
});
pub struct IcedLogger {
    sender: UnboundedSender<String>,
    receiver: Arc<RwLock<UnboundedReceiver<String>>>,
    // level: RwLock<log::LevelFilter>,
}
impl IcedLogger {
    // pub fn receiver()
    // pub async fn set_level(&self, level: LevelFilter) {
    //     *self.level.write().await = level;
    // }
}

impl log::Log for IcedLogger {
    fn enabled(&self, metadata: &log::Metadata) -> bool {
        if metadata.level() <= log::max_level() {
            let target = metadata.target();
            let is_iced_internal = target.starts_with("iced")
                || target.starts_with("winit")
                || target.starts_with("glium")
                || target.starts_with("softbuffer")
                || target.starts_with("gilrs");

            if is_iced_internal {
                return false; // 👈 屏蔽
            }
        }
        true
    }

    fn log(&self, record: &log::Record) {
        if self.enabled(record.metadata()) {
            let time = chrono::Local::now().format("%m/%d %H:%M:%6f");
            let msg = format!("{} {} {}", time, record.level(), record.args());
            let _ = self.sender.send(msg);
        }
    }

    fn flush(&self) {
        // todo!()
    }
}
//这个必须写在外面
pub fn receive_logs() -> Subscription<String> {
    iced::Subscription::run(|| {
        let rx = GLOBAL_LOGGER.receiver.clone();
        unfold((), move |_| {
            let rx = rx.clone();
            async move {
                let line = rx.write().await.recv().await.unwrap_or_default();
                Some((line, ()))
            }
        })
    })
}

pub fn init_logger(level: LevelFilter) {
    log::set_logger(&*GLOBAL_LOGGER).unwrap();
    log::set_max_level(level);
}
