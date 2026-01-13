use std::{env, str::FromStr};

use clap::Parser;
use proxy2_rs::{
    app_config::AppConfig, factory::inbound_factory::InBoundFactory, start_args::StartArgs,
};

#[tokio::main]
async fn main() {
    env_logger::builder()
        .filter_level(log::LevelFilter::Trace)
        .init();

    let args = StartArgs::parse();
    let config_path = match args.config() {
        Some(path) => path.clone(),
        None => {
            let current_dir = env::current_dir().expect("get current directory failed!");
            current_dir.join("config.toml")
        }
    };
    let config_content = std::fs::read_to_string(config_path).expect("read config content failed!");
    let config = AppConfig::from_str(&config_content).expect("config format is incorrect.");
    let log_config = config.log();
    let lf = log_config.level_filter().expect("log level failed!");
    let path = log_config.access_path();
    fern::Dispatch::new()
        .level(lf)
        .chain(std::io::stdout())
        .chain(fern::log_file(path).expect("log to file failed!"))
        .apply()
        .expect("log config failed!");
    let inbound = InBoundFactory::get(config.inbound()).await;
    inbound.start().await;
}
