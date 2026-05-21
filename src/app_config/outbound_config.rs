use std::{
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    path::PathBuf,
};

use crate::dns_resolver::resolve_dns_pick_fastet;

use anyhow::Result;
#[derive(Debug, Clone, serde::Deserialize, PartialEq)]
#[serde(tag = "protocol", rename_all = "lowercase")]
pub enum OutBoundTypeConfig {
    Ethan(EthanOutBoundConfig),
    Direct(DirectOutputConfig),
}

impl OutBoundTypeConfig {
    pub fn eq_name_ignore_case(&self, name: impl AsRef<str>) -> bool {
        match self {
            OutBoundTypeConfig::Ethan(ethan_out_bound_config) => {
                ethan_out_bound_config.name.eq_ignore_ascii_case(name.as_ref())
            }
            OutBoundTypeConfig::Direct(direct_output_config) => {
                direct_output_config.name.eq_ignore_ascii_case(name.as_ref())
            }
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
    crt_path: Option<PathBuf>,//如果是信任的公开证书，则可以忽略
}
impl EthanOutBoundConfig {
    pub fn new(
        name: String, addr: String, port: u16, uid: String, pwd: String,
        crt_path: Option<PathBuf>,
    ) -> Self {
        Self { name, addr, port, uid, pwd, crt_path }
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
    pub fn tls(&self) -> &Option<PathBuf> {
        &self.crt_path
    }
    pub fn addr(&self)->&str{
        &self.addr
    }
    pub async fn socket_addr(&self) -> Result<SocketAddr> {
        let ipaddr: IpAddr = if let Ok(ipv4) = self.addr.parse::<Ipv4Addr>() {
            ipv4.into()
        } else if let Ok(ipv6) = self.addr.parse::<Ipv6Addr>() {
            ipv6.into()
        } else {
            resolve_dns_pick_fastet(&self.addr).await?
        };
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
            crt_path="~/DevSpace/certs/dev.ubuntu.crt""#,
        )?;
        if let OutBoundTypeConfig::Ethan(ethan_out_config) = outbound_config {
            assert_eq!("ethan", ethan_out_config.name());
            assert_eq!("u", ethan_out_config.uid());
            assert_eq!("p", ethan_out_config.pwd());
            assert_eq!(10800, ethan_out_config.port);
            assert_eq!("127.0.0.1", ethan_out_config.addr);
            assert!(ethan_out_config.tls().is_some());
            if let Some(crt_path) = ethan_out_config.tls() {
                assert_eq!(
                    "~/DevSpace/certs/dev.ubuntu.crt",
                    crt_path.display().to_string()
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
