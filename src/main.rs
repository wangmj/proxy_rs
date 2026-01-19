use std::{
    fs::{self},
    panic,
    path::Path,
};

use proxy_rs::{app_config::APP_CONFIG, factory::inbound_factory::InBoundFactory};

#[tokio::main]
async fn main() {
    let log_config = APP_CONFIG.log();
    let lf = log_config.level_filter().expect("log level failed!");
    let path = log_config.access_path();
    touch_file_if_noexist(path);
    fern::Dispatch::new()
        .level(lf)
        .chain(std::io::stdout())
        .chain(fern::log_file(path).expect("log to file failed!"))
        .apply()
        .expect("log config failed!");
    let inbound = InBoundFactory::get(APP_CONFIG.inbound()).await;
    inbound.start().await;
}

// const SUPPORT_FILE_EXTENSION_NAME: [&'static str; 2] = ["log", "txt"];
fn touch_file_if_noexist(p: impl AsRef<Path>) {
    let p = p.as_ref();

    if !p.exists() {
        let parent_dir = match p.parent() {
            Some(parent) => parent,
            None => panic!("log file path is incorrdct"),
        };
        if !parent_dir.exists() {
            match fs::create_dir_all(parent_dir) {
                Ok(_) => {}
                Err(err) => panic!("创建目录：{} 失败，原因：{}", parent_dir.display(), err),
            }
        }
        if let Err(err) = fs::File::create(p) {
            panic!("创建文件：{}失败，原因：{}", p.display(), err);
        }
    }
}
