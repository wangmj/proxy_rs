use std::{
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    path::PathBuf,
};

use crate::dns_resolver::{pick_fastet_ipadd, resolve_dns};

use anyhow::{Result, anyhow};
use serde::Deserialize;
#[derive(Debug, Clone, serde::Deserialize, PartialEq)]
#[serde(tag = "protocol", rename_all = "lowercase")]
pub enum OutBoundTypeConfig {
    Ethan(EthanOutBoundConfig),
    Direct(DirectOutputConfig),
}

impl OutBoundTypeConfig {
    pub fn eq_name_ignore_case(&self, name: impl AsRef<str>) -> bool {
        match self {
            OutBoundTypeConfig::Ethan(ethan_out_bound_config) => ethan_out_bound_config
                .name
                .eq_ignore_ascii_case(name.as_ref()),
            OutBoundTypeConfig::Direct(direct_output_config) => direct_output_config
                .name
                .eq_ignore_ascii_case(name.as_ref()),
        }
    }
}

#[derive(Debug, Clone, serde::Deserialize, PartialEq)]
pub struct EthanOutBoundConfig {
    name: String,
    addr: String,
    port: u16,
    uid: String,
    pwd: String,
    tls: Option<TlsClientConfig>,
}
impl EthanOutBoundConfig {
    pub fn new(
        name: String,
        addr: String,
        port: u16,
        uid: String,
        pwd: String,
        tls: Option<TlsClientConfig>,
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
    pub fn name(&self) -> &str {
        &self.name
    }
    pub fn uid(&self) -> &str {
        &self.uid
    }
    pub fn pwd(&self) -> &str {
        &self.pwd
    }
    pub fn tls(&self) -> &Option<TlsClientConfig> {
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

#[derive(Debug, Clone, serde::Deserialize, PartialEq)]
pub struct DirectOutputConfig {
    name: String,
}
impl DirectOutputConfig {
    pub fn new(name: impl Into<String>) -> Self {
        Self { name: name.into() }
    }
}

#[derive(Debug, Deserialize, Clone, PartialEq)]
pub struct TlsClientConfig {
    pub use_tls: bool,
    pub domain_name: String,
    pub crt_path: PathBuf, //如果是信任的密钥，则可以忽略
}

#[cfg(test)]
mod test {
    use super::*;
    #[test]
    fn outbound_ethan_config_parse_test() -> Result<()> {
        // let toml_value = toml::Value::Table::from_str(config_str);
        let outbound_config: OutBoundTypeConfig = toml::from_str(
            r#"name="ethan"
            protocol = "ethan"
            uid = "u"
            pwd = "p"
            port = 10800
            addr = "127.0.0.1"

            [tls]
            use_tls = true
            domain_name="dev.ubuntu"
            crt_path="~/DevSpace/certs/dev.ubuntu.crt""#,
        )?;
        if let OutBoundTypeConfig::Ethan(ethan_out_config) = outbound_config {
            assert_eq!("ethan", ethan_out_config.name());
            assert_eq!("u", ethan_out_config.uid());
            assert_eq!("p", ethan_out_config.pwd());
            assert_eq!(10800, ethan_out_config.port);
            assert_eq!("127.0.0.1", ethan_out_config.addr);
            assert!(ethan_out_config.tls().is_some());
            if let Some(tls_config) = ethan_out_config.tls() {
                assert_eq!("dev.ubuntu", tls_config.domain_name);
                assert_eq!(
                    "~/DevSpace/certs/dev.ubuntu.crt",
                    tls_config.crt_path.display().to_string()
                );
            }
        } else {
            panic!("incorrect!");
        }
        Ok(())
    }
    #[test]
    fn outbound_direct_config_parse_test() -> Result<(), Box<dyn std::error::Error>> {
        let outbound_config: OutBoundTypeConfig = toml::from_str(
            r#"name="direct"
            protocol="direct""#,
        )?;
        if let OutBoundTypeConfig::Direct(direct) = outbound_config {
            assert_eq!(direct.name, "direct");
            Ok(())
        } else {
            Err("outbound config is direct config".into())
        }
    }
}
