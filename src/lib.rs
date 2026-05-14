pub mod app_config;
pub mod direct;
pub mod dns_resolver;
pub mod ethan;
pub mod factory;
pub mod socks;
pub mod start_args;
pub mod traits;

mod geoip_helper;
mod utils;

use std::fmt::{Debug, Display};

// pub use app_config::app_config::{APP_CONFIG, AppConfig};
pub use app_config::config::*;
pub use app_config::*;
use tokio::sync::broadcast::Receiver;

#[derive(Debug)]
pub enum ProxyError {
    Socks5VersionIncorrect,
    Socks5AuthError(String),
    Socks5NoSupportAuthMethod,
    Socks5AuthReject,
    Socks5CmdParseError(u8),
    Socks5UnknownAtyp,
    EthanAuthFailed(String),
    EthanAuthUserPwdIncorrect(String, String),
    EthanBindError(String),
    TlsHandshakeError(std::io::Error),
    EthanAuthRequestParseError,
    LengthNotMatchedAggree(String),
    Socks5NotSupportAuthmethod,
}
impl Display for ProxyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ProxyError::Socks5AuthError(msg) => write!(f, "Socks5 auth failed! {msg}"),
            ProxyError::Socks5VersionIncorrect => write!(f, "Socks5 version is incorrect"),
            ProxyError::Socks5NoSupportAuthMethod => {
                write!(
                    f,
                    "There is no auth method supported by both the client and the server"
                )
            }
            ProxyError::Socks5CmdParseError(val) => {
                write!(f, "Unknown Socks5 command type value:{val}")
            }
            ProxyError::Socks5UnknownAtyp => write!(f, "UnKnwon ATYP or parse atyp address faild!"),
            ProxyError::EthanAuthUserPwdIncorrect(u, p) => {
                write!(f, "User and pwd not incorrect, {u} {p}")
            }
            ProxyError::EthanAuthFailed(msg) => write!(f, "Ethan auth failed, reason: {msg}"),
            ProxyError::EthanBindError(msg) => write!(f, "Ethan bind failed, reason: {msg}"),
            ProxyError::TlsHandshakeError(error) => write!(f, "Tls hand shake failed, {error}"),
            ProxyError::EthanAuthRequestParseError => {
                write!(f, "Ethan proto auth request parse failed!")
            }
            ProxyError::LengthNotMatchedAggree(msg) => {
                write!(f, "The length is not matched with aggree, {msg}")
            }
            ProxyError::Socks5NotSupportAuthmethod => write!(f,"Server doesnot supported that auth method"),
            ProxyError::Socks5AuthReject => write!(f,"Server reject auth"),
                    }
    }
}

impl std::error::Error for ProxyError {}


pub fn shutdown_listener() -> Receiver<()> {
    let (sender, rev) = tokio::sync::broadcast::channel(1);
    tokio::spawn(async move {
        tokio::signal::ctrl_c()
            .await
            .expect("failed to listen ctrl+c");
        log::info!("shutdown......");
        let _ = sender.send(());
    });
    rev
}
