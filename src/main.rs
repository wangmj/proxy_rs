use std::{
    fs::{self},
    io, panic,
    path::Path,
};

use proxy_rs::{APP_CONFIG, factory::inbound_factory::InBoundFactory};

// #[tokio::main]
fn main() -> io::Result<()> {
    program_init();

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_io()
        .enable_time()
        .max_blocking_threads(512) // default value
        .build()?;
    runtime.block_on(async {
        let inbound = InBoundFactory::get(APP_CONFIG.inbound().clone(), APP_CONFIG.dns().clone());
        inbound.start().await;
    });
    Ok(())
}
//整体的初始化
fn program_init() {
    init_logger();
}
//初始化日志
fn init_logger() {
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
}
// const SUPPORT_FILE_EXTENSION_NAME: [&'static str; 2] = ["log", "txt"];
fn touch_file_if_noexist(p: impl AsRef<Path>) {
    let p = p.as_ref();

    if !p.exists() {
        let parent_dir = match p.parent() {
            Some(parent) => parent,
            None => panic!("log file path is incorrdct"),
        };
        if !parent_dir.exists()
            && let Err(err) = fs::create_dir_all(parent_dir)
        {
            panic!("创建目录：{} 失败，原因：{}", parent_dir.display(), err);
        }
        if let Err(err) = fs::File::create(p) {
            panic!("创建文件：{}失败，原因：{}", p.display(), err);
        }
    }
}
