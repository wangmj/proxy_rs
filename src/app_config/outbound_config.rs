use std::{
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    path::PathBuf,
};

use crate::dns_resolver::{pick_fastet_ipadd, resolve_dns};

use anyhow::{Result, anyhow};
use serde::Deserialize;
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq)]
pub enum OutBoundTypeConfig {
    Ethan(EthanOutBoundConfig),
    Freedom(FreedomOutputConfig),
}

impl OutBoundTypeConfig {
    pub fn eq_name_ignore_case(&self, name: impl AsRef<str>) -> bool {
        match self {
            OutBoundTypeConfig::Ethan(ethan_out_bound_config) => ethan_out_bound_config
                .name
                .eq_ignore_ascii_case(name.as_ref()),
            OutBoundTypeConfig::Freedom(freedom_output_config) => freedom_output_config
                .name
                .eq_ignore_ascii_case(name.as_ref()),
        }
    }
}
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq)]
pub struct EthanOutBoundConfig {
    name: String,
    addr: String,
    port: u16,
    uid: String,
    pwd: String,
    tls: TlsClientConfig,
}
impl EthanOutBoundConfig {
    pub fn new(
        name: String,
        addr: String,
        port: u16,
        uid: String,
        pwd: String,
        tls: TlsClientConfig,
    ) -> Self {
        Self {
            name,
            addr,
            port,
            uid,
            pwd,
            tls,
        }
    }
    pub fn name(&self)->&str{
        &self.name
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

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq)]
pub struct FreedomOutputConfig {
    name: String,
}
impl FreedomOutputConfig {
    pub fn new(name: impl Into<String>) -> Self {
        Self { name: name.into() }
    }
}

#[derive(Debug, serde::Serialize, Deserialize, Clone, PartialEq)]
pub struct TlsClientConfig {
    pub use_tls: bool,
    pub domain_name: Option<String>,
    pub crt_path: Option<PathBuf>, //如果是信任的密钥，则可以忽略
}
