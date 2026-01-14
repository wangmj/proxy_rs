use anyhow::{Result, anyhow};
use clap::Parser;
use serde::{Deserialize, Deserializer};
use std::{
    env, net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr}, path::{Path, PathBuf}, str::FromStr, sync::LazyLock
};

use crate::{dns_resolver::{pick_fastet_ipadd, resolve_dns}, start_args::StartArgs};
pub static APP_CONFIG:LazyLock<AppConfig>=LazyLock::new(||{get_app_config_from_args()});

fn get_app_config_from_args()->AppConfig{
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
    error: ErrorLogConfig,
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

#[derive(Debug, serde::Serialize, serde::Deserialize, PartialEq)]
#[serde(untagged)] // 可选：避免枚举项的字段冲突，仅在枚举项有不同结构体字段时需要
pub enum InBoundTypeConfig {
    Socks5(SocksInBoundConfig),
    Ethan(EthanInBoundConfig),
}
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq)]
pub struct SocksInBoundConfig {
    port: u16,
    uid: Option<String>,
    pwd: Option<String>,
}
impl SocksInBoundConfig {
    pub fn port(&self) -> u16 {
        self.port
    }
    pub fn uid(&self) -> Option<&str> {
        self.uid.as_deref()
    }
    pub fn pwd(&self) -> Option<&str> {
        self.pwd.as_deref()
    }
}
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq)]
pub struct EthanInBoundConfig {
    port: u16,
    uid: Option<String>,
    pwd: Option<String>,
}
impl EthanInBoundConfig {
    pub fn port(&self) -> u16 {
        self.port
    }
    pub fn uid(&self) -> Option<String> {
        self.uid.as_ref().map(|x| x.to_string())
    }
    pub fn pwd(&self) -> Option<String> {
        self.pwd.as_ref().map(|x| x.to_string())
    }
}

//输入的类型的中间结构体
#[derive(Debug, serde::Deserialize)]
struct InputBoundProtocolIntermediate {
    protocol: String,
    #[serde(flatten)] // 扁平化：将 TOML 中的其他字段直接解析到 config 中（避免嵌套）
    config: toml::Value, // 先以原始 Value 存储配置，后续再反序列化为具体结构体
}

// 自定义反序列化函数：核心逻辑——根据 protocol_type 映射枚举
fn deserialize_protocol<'de, D>(deserializer: D) -> Result<InBoundTypeConfig, D::Error>
where
    D: Deserializer<'de>,
{
    let intermediate = InputBoundProtocolIntermediate::deserialize(deserializer)?;
    let protocol = intermediate.protocol.to_lowercase();
    let config_str = toml::ser::to_string(&intermediate.config)
        .map_err(|e| serde::de::Error::custom(e.to_string()))?;
    match protocol.as_str() {
        "socks5" => {
            let socks_input_config: SocksInBoundConfig = toml::de::from_str(&config_str)
                .map_err(|e| serde::de::Error::custom(e.to_string()))?;
            Ok(InBoundTypeConfig::Socks5(socks_input_config))
        }
        "ethan" => {
            let ethan_input_config: EthanInBoundConfig =
                toml::from_str(&config_str).map_err(|e| serde::de::Error::custom(e.to_string()))?;
            Ok(InBoundTypeConfig::Ethan(ethan_input_config))
        }
        _other => Err(serde::de::Error::unknown_variant(
            _other,
            &["socks5", "ethan"],
        )),
    }
}
#[derive(Debug, serde::Serialize, serde::Deserialize, PartialEq)]
pub enum OutputBoundTypeConfig {
    Ethan(EthanOutputConfig),
    Freedom(FreedomOutputConfig),
}
#[derive(Debug,Clone, serde::Serialize, serde::Deserialize, PartialEq)]
pub struct EthanOutputConfig {
    addr: String,
    port: u16,
    uid: Option<String>,
    pwd: Option<String>,
}
impl EthanOutputConfig {
    pub async fn socket_addr(&self) -> Result<SocketAddr> {
        let ipaddr: IpAddr;
        if let Ok(ipv4) = self.addr.parse::<Ipv4Addr>() {
            ipaddr = ipv4.into();
        } else if let Ok(ipv6) = self.addr.parse::<Ipv6Addr>() {
            ipaddr = ipv6.into();
        } else {
            let ips = resolve_dns(&self.addr).await?;
            match pick_fastet_ipadd(&ips, self.port).await {
                Some(ip) => ipaddr = ip,
                None => return Err(anyhow!("根据域名：{}未能解析道IP地址", self.addr)),
            }
        }
        Ok(SocketAddr::new(ipaddr, self.port))
    }
}
#[derive(Debug,Clone,Copy, serde::Serialize, serde::Deserialize, PartialEq)]
pub struct FreedomOutputConfig;

#[derive(Debug, serde::Deserialize)]
struct OutBoundIntermediate {
    protocol: String,
    #[serde(flatten)]
    config: toml::Value,
}
fn deserialize_output_protocol<'de, D>(deserializer: D) -> Result<OutputBoundTypeConfig, D::Error>
where
    D: Deserializer<'de>,
{
    let intermediate = OutBoundIntermediate::deserialize(deserializer)?;
    let protocol = intermediate.protocol.to_lowercase();
    let config_str = toml::ser::to_string(&intermediate.config)
        .map_err(|e| serde::de::Error::custom(e.to_string()))?;

    match protocol.as_str() {
        "ethan" => {
            let ethan: EthanOutputConfig =
                toml::from_str(&config_str).map_err(|e| serde::de::Error::custom(e.to_string()))?;
            Ok(OutputBoundTypeConfig::Ethan(ethan))
        }
        "freedom" => Ok(OutputBoundTypeConfig::Freedom(FreedomOutputConfig)),
        _other => Err(serde::de::Error::unknown_variant(
            _other,
            &["ethan", "freedom"],
        )),
    }
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
"##;
        let appconfig = AppConfig::from_str(config)?;
        assert_eq!(appconfig.log.access.level, "trace");
        assert_eq!(
            appconfig.log.access.path,
            PathBuf::from("/var/log/rs_proxy/access.log")
        );
        assert_eq!(
            appconfig.log.error.path,
            PathBuf::from("/var/log/rs_proxy/error.log")
        );

        let socks_input_config = SocksInBoundConfig {
            port: 1080,
            uid: None,
            pwd: None,
        };
        assert_eq!(
            appconfig.inbound,
            InBoundTypeConfig::Socks5(socks_input_config)
        );

        let ethan_output_config = EthanOutputConfig {
            addr: "127.0.0.1".into(),
            port: 10800,
            uid: Some("ethan.wang".into()),
            pwd: Some("pass01!".into()),
        };
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
        access.level = "trace"
        access.path = "/var/log/rs_proxy/access.log"
        error.path = "/var/log/rx_proxy/error.log"
        [inbound]
        protocol = "ethan"
        port = 10800

        [outbound]
        protocol = "freedom"
        "##;
        let config = AppConfig::from_str(&str)?;
        let ethan = EthanInBoundConfig {
            port: 10800,
            uid: None,
            pwd: None,
        };
        assert_eq!(config.inbound, InBoundTypeConfig::Ethan(ethan));

        assert_eq!(
            config.outbound,
            OutputBoundTypeConfig::Freedom(FreedomOutputConfig)
        );
        Ok(())
    }
}
