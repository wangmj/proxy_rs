#![windows_subsystem = "windows"]

mod proxy_gui;
mod system_proxy;
mod iced_logger;

use proxy_core::{AppConfig, inject_config};
use std::env;

use proxy_gui::ProxyGUI;

use crate::iced_logger::init_logger;
fn main() {
    init_config();
    if let Err(err) = iced::application(ProxyGUI::new, ProxyGUI::update, ProxyGUI::view)
        .subscription(ProxyGUI::subscription)
        .run()
    {
        eprintln!("{err}");
    }
}

fn init_config() {
    let current_dir = env::current_exe().expect("get current exe path failed!");
    let base_dir = current_dir.parent().expect("get parent dir failed!");
    let default_config = base_dir.join("config.json");
    let config = AppConfig::open_readfile(default_config).expect("read file failed!");

    init_logger(config.log().level().unwrap_or(log::Level::Info).to_level_filter());

    inject_config(config);
}
