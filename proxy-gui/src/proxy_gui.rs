use iced::font::Weight;
use iced::widget::text::LineHeight;
use iced::widget::{Rule, rule};
use proxy_core::{
    InBoundTypeConfig, factory::inbound_factory::InBoundFactory, get_config,
    traits::proxy_inbound::InBoundProxy,
};
use std::env;
use std::sync::Arc;

use anyhow::Result;
use iced::widget::{Column, Space, checkbox, column, container, scrollable, text, text::Shaping};
use iced::{Color, Element, Font, Length, Subscription, Task, Theme};

use crate::iced_logger;
use crate::system_proxy;

pub struct ProxyGUI {
    proxy: Arc<Box<dyn InBoundProxy>>,
    system_proxy_enabled: bool,
    logs: Vec<String>,
}

#[derive(Debug, Clone)]
pub enum Message {
    Start,
    Started,
    Stop,
    Stopped,
    Newlog(String),
}

impl Default for ProxyGUI {
    fn default() -> Self {
        Self::new()
    }
}

impl ProxyGUI {
    pub fn new() -> Self {
        let inbound =
            InBoundFactory::get(get_config().inbound().clone(), get_config().dns().clone());
        Self { proxy: inbound.into(), system_proxy_enabled: false, logs: Vec::new() }
    }
    pub fn subscription(&self) -> Subscription<Message> {
        iced_logger::receive_logs().map(|x| Message::Newlog(x))
    }
    pub fn view(&self) -> Element<'_, Message> {
        let is_running = self.system_proxy_enabled;

        let proxy_check = checkbox(self.system_proxy_enabled)
            .label(if is_running { "停止 SOCKS5 代理" } else { "启动 SOCKS5 代理" })
            .width(Length::Fill)
            .on_toggle(move |_| if is_running { Message::Stop } else { Message::Start });

        let logs = self.logs.iter().map(|s: &String| {
            let color = if s.contains("ERROR") {
                Color::from_rgb(1.0, 0.2, 0.2)
            } else if s.contains("WARN") {
                Color::from_rgb(1.0, 0.8, 0.0)
            } else {
                Color::BLACK
            };

            let s = s.replace("\r\n", "").replace("\r", "").replace("\n", "").replace("\t", "");
            text(s)
                .color(color)
                .shaping(Shaping::Advanced)
                .wrapping(text::Wrapping::WordOrGlyph)
                // .line_height(LineHeight::Relative(1.1))
                .width(Length::Fill)
                .into()
        });

        let log_area = scrollable(container(column(logs).width(Length::Fill).spacing(2)))
            .anchor_bottom()
            .height(Length::Fill)
            .width(Length::Fill);

        let content = column![
            text("SOCKS5 代理工具")
                .font(Font { weight: Weight::Bold, ..Default::default() })
                .size(24),
            Space::new().width(Length::Fill).height(10),
            rule::horizontal(1),
            Space::new().width(Length::Fill).height(10),
            proxy_check,
            Space::new().width(Length::Fill).height(20),
            rule::horizontal(1),
            Space::new().width(Length::Fill).height(20),
            // system_proxy,
            // Space::new().width(0).height(20),
            text("日志").size(18).color(Color::from_rgb(0.5f32, 0.5, 0.5)),
            log_area
        ]
        .padding(20)
        .spacing(5)
        .width(Length::Fill);

        container(content).width(Length::Fill).into()
    }
    pub fn update(&mut self, msg: Message) -> Task<Message> {
        match msg {
            Message::Start => {
                log::info!("starting...");
                let proxy = self.proxy.clone();
                Task::perform(
                    async move {
                        log::info!("starting...");
                        let port = match &**get_config().inbound() {
                            InBoundTypeConfig::Socks5(socks_in_bound_config) => {
                                socks_in_bound_config.port()
                            }
                            InBoundTypeConfig::Ethan(ethan_in_bound_config) => {
                                ethan_in_bound_config.port()
                            }
                        };
                        if system_proxy::enable_socks5_system_proxy("127.0.0.1", port).is_ok() {
                            tokio::spawn(async move {
                                proxy.start().await;
                            });
                           return true;
                        }
                        return false;
                    },
                    |flag| if flag{
                        Message::Started
                    }else{
                        Message::Stopped
                    },
                )
            }
            Message::Stop => {
                log::info!("stoping..");
                let proxy = self.proxy.clone();
                Task::perform(
                    async move {
                        proxy.stop().await;
                    },
                    |_| Message::Stopped,
                )
            }
            Message::Started => {
                self.system_proxy_enabled = true;
                log::info!("代理启动成功...");
                Task::none()
            }
            Message::Stopped => {
                if system_proxy::disalbe_socks5_system_proxy().is_ok() {
                    log::info!("代理关闭成功...");
                } else {
                    log::info!("代理关闭失败...");
                }
                self.system_proxy_enabled = false;
                Task::none()
            }

            Message::Newlog(log) => {
                self.logs.push(log);
                Task::none()
            }
        }
    }
}

fn start_proxy(proxy: Arc<Box<dyn InBoundProxy>>) -> Result<()> {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_io()
        .enable_time()
        .max_blocking_threads(512) // default value
        .build()?;

    runtime.spawn(async move {});

    Ok(())
}
// fn stop_proxy
