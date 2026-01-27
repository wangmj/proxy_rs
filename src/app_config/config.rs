use super::inbound_config::*;
use super::outbound_config::*;
use anyhow::Result;
use clap::Parser;
use std::{
    env,
    path::{Path, PathBuf},
    str::FromStr,
    sync::LazyLock,
};

use crate::start_args::StartArgs;
pub static APP_CONFIG: LazyLock<AppConfig> = LazyLock::new(get_app_config_from_args);

fn get_app_config_from_args() -> AppConfig {
    let args = StartArgs::parse();
    let config_path = match args.config() {
        Some(path) => path.clone(),
        None => {
            let current_dir = env::current_dir().expect("get current directory failed!");
            current_dir.join("config.toml")
        }
    };
    let config_content = std::fs::read_to_string(config_path).expect("read config content failed!");
    AppConfig::from_str(&config_content).expect("config format is incorrect.")
}

#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub struct AppConfig {
    log: LogConfig,
    #[serde(deserialize_with = "deserialize_protocol")]
    inbound: InBoundTypeConfig,
    #[serde(deserialize_with = "deserialize_output_protocol")]
    outbound: OutputBoundTypeConfig,
}
impl AppConfig {
    pub fn inbound(&self) -> &InBoundTypeConfig {
        &self.inbound
    }
    pub fn outbound(&self) -> &OutputBoundTypeConfig {
        &self.outbound
    }
    pub fn log(&self) -> &LogConfig {
        &self.log
    }
}

impl FromStr for AppConfig {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        let f: AppConfig = toml::from_str(s)?;
        Ok(f)
    }
}

#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub struct LogConfig {
    access: AccessLogConfig,
    // error: ErrorLogConfig,
}
impl LogConfig {
    pub fn level(&self) -> Result<log::Level> {
        let level = log::Level::from_str(self.access.level.to_lowercase().as_str())?;
        Ok(level)
    }
    pub fn level_filter(&self) -> Result<log::LevelFilter> {
        let lf = log::LevelFilter::from_str(self.access.level.to_lowercase().as_str())?;
        Ok(lf)
    }
    pub fn access_path(&self) -> &Path {
        self.access.path.as_path()
    }
}

#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub struct AccessLogConfig {
    level: String,
    path: PathBuf,
}
#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub struct ErrorLogConfig {
    path: PathBuf,
}

#[cfg(test)]
mod test {

    use super::*;
    use anyhow::Result;

    #[test]
    fn app_config_fromstr_test() -> Result<()> {
        let config = r##"
        [log]
        access.level = "trace"
        access.path = "/var/log/rs_proxy/access.log"
        error.path = "/var/log/rs_proxy/error.log"

        [inbound]
        protocol = "socks5"
        port = 1080

        [outbound]
        protocol = "ethan"
        uid = "ethan.wang"
        pwd = "pass01!"
        port = 10800
        addr = "127.0.0.1"
        [outbound.tls]
        use_tls=true
        domain_name="localhost"
        crt_path=""
        [outbound.dns]
        resolver="local"
        server=["8.8.8.8"]
"##;
        let appconfig = AppConfig::from_str(config)?;
        assert_eq!(appconfig.log.access.level, "trace");
        assert_eq!(
            appconfig.log.access.path,
            PathBuf::from("/var/log/rs_proxy/access.log")
        );
        // assert_eq!(
        //     appconfig.log.error.path,
        //     PathBuf::from("/var/log/rs_proxy/error.log")
        // );

        let socks_input_config = SocksInBoundConfig::new(1080, None, None);
        assert_eq!(
            appconfig.inbound,
            InBoundTypeConfig::Socks5(socks_input_config)
        );

        let ethan_output_config = EthanOutBoundConfig::new(
            "127.0.0.1".into(),
            10800,
            "ethan.wang".into(),
            "pass01!".into(),
            TlsClientConfig {
                use_tls: true,
                domain_name: Some("localhost".into()),
                crt_path: Some("".into()),
            },
            DnsConfig {
                resolver: DNSResolver::Local,
                server: Some(["8.8.8.8".into()].to_vec()),
            },
        );
        assert_eq!(
            appconfig.outbound,
            OutputBoundTypeConfig::Ethan(ethan_output_config)
        );
        Ok(())
    }

    #[test]
    fn app_config_fromstr_test2() -> Result<()> {
        let str = r##"
        [log]
        access.level = "info"
        access.path = "/var/log/rs_proxy/access.log"
        error.path = "/var/log/rx_proxy/error.log"
        [inbound]
        protocol = "ethan"
        port = 10800
        uid = "uid"
        pwd = "pwd"
        [inbound.tls]
        use_tls = true
        crt_path = "localhost.crt"
        key_path = "localhost.key"
        domain_name = "localhost"

        [outbound]
        protocol = "freedom"
        "##;
        let config = AppConfig::from_str(&str)?;
        let ethan = EthanInBoundConfig::new(
            10800,
            "uid".to_string(),
            "pwd".to_string(),
            TlsServerConfig {
                use_tls: true,
                crt_path: Some("localhost.crt".into()),
                key_path: Some("localhost.key".into()),
                domain_name: Some("localhost".into()),
            },
        );
        assert_eq!(config.inbound, InBoundTypeConfig::Ethan(ethan));

        assert_eq!(
            config.outbound,
            OutputBoundTypeConfig::Freedom(FreedomOutputConfig)
        );
        Ok(())
    }
}
