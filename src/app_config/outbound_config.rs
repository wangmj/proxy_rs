use std::{net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr}, path::PathBuf};

use crate::dns_resolver::{pick_fastet_ipadd, resolve_dns};

use anyhow::{Result,anyhow};
use serde::{Deserialize, Deserializer};

#[derive(Debug, serde::Serialize, serde::Deserialize, PartialEq)]
pub enum OutputBoundTypeConfig {
    Ethan(EthanOutBoundConfig),
    Freedom(FreedomOutputConfig),
}
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq)]
pub struct EthanOutBoundConfig {
    addr: String,
    port: u16,
    uid: String,
    pwd: String,
    tls: TlsClientConfig,
}
impl EthanOutBoundConfig {
    pub fn new(addr:String,port:u16,uid:String,pwd:String,tls:TlsClientConfig)->Self{
        Self { addr, port, uid, pwd, tls }
    }
    pub fn uid(&self) -> &str {
        &self.uid
    }
    pub fn pwd(&self) -> &str {
        &self.pwd
    }
    pub fn tls(&self) -> &TlsClientConfig {
        &self.tls
    }
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

#[derive(Debug, Clone, Copy, serde::Serialize, serde::Deserialize, PartialEq)]
pub struct FreedomOutputConfig;

#[derive(Debug, serde::Deserialize)]
struct OutBoundIntermediate {
    protocol: String,
    #[serde(flatten)]
    config: toml::Value,
}
pub fn deserialize_output_protocol<'de, D>(deserializer: D) -> Result<OutputBoundTypeConfig, D::Error>
where
    D: Deserializer<'de>,
{
    let intermediate = OutBoundIntermediate::deserialize(deserializer)?;
    let protocol = intermediate.protocol.to_lowercase();
    let config_str = toml::ser::to_string(&intermediate.config)
        .map_err(|e| serde::de::Error::custom(e.to_string()))?;

    match protocol.as_str() {
        "ethan" => {
            let ethan: EthanOutBoundConfig =
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

#[derive(Debug, serde::Serialize, Deserialize, Clone, PartialEq)]
pub struct TlsClientConfig {
    pub use_tls: bool,
    pub domain_name: Option<String>,
    pub crt_path: Option<PathBuf>, //如果是信任的密钥，则可以忽略
}