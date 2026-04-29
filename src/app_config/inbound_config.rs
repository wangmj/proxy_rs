use std::path::PathBuf;

use serde::{
    Deserialize, Deserializer,
};

#[derive(Debug, serde::Deserialize, PartialEq)]
#[serde(tag="protocol",rename_all="lowercase")] // 可选：避免枚举项的字段冲突，仅在枚举项有不同结构体字段时需要
pub enum InBoundTypeConfig {
    Socks5(SocksInBoundConfig),
    Ethan(EthanInBoundConfig),
}
#[derive(Debug, Clone, serde::Deserialize, PartialEq)]
pub struct SocksInBoundConfig {
    port: u16,
    uid: Option<String>,
    pwd: Option<String>,
}
impl SocksInBoundConfig {
    pub fn new(port: u16, uid: Option<String>, pwd: Option<String>) -> Self {
        Self {
            port,
            uid,
            pwd,
        }
    }
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



#[derive(Debug, Clone, serde::Deserialize, PartialEq)]
pub struct EthanInBoundConfig {
    port: u16,
    uid: String,
    pwd: String,
    tls: Option<TlsServerConfig>,
}
impl EthanInBoundConfig {
    pub fn new(port: u16, uid: String, pwd: String, tls_config: Option<TlsServerConfig>) -> Self {
        Self {
            port,
            uid,
            pwd,
            tls: tls_config,
        }
    }
    pub fn tls(&self) -> &Option<TlsServerConfig> {
        &self.tls
    }
    pub fn port(&self) -> u16 {
        self.port
    }
    pub fn uid(&self) -> &str {
        &self.uid
    }
    pub fn pwd(&self) -> &str {
        &self.pwd
    }
}

#[derive(Debug, Deserialize, Clone, PartialEq)]
pub struct TlsServerConfig {
    pub crt_path: PathBuf,   //公钥+证书链存放地址,
    pub key_path: PathBuf,   //私钥存放地址
    pub domain_name: String, //域名
}

// impl TlsServerConfig
#[cfg(test)]
mod test {
    use std::{error::Error, path::PathBuf};

    use crate::{ InBoundTypeConfig};

    #[test]
    fn inbound_toml_parse_test() -> Result<(), Box<dyn std::error::Error>> {
        let config_str = r#"
        protocol = "ethan"
        port = 10800
        uid = "ethan.wang"
        pwd = "pass01!"

        [tls]
        crt_path = "localhost.crt"
        key_path = "localhost.key"
        domain_name = "localhost""#;

        let config: InBoundTypeConfig = toml::from_str(config_str)?;
        match config {
            InBoundTypeConfig::Socks5(_) => {
                return Err("the config should be enthan config".into());
            }
            InBoundTypeConfig::Ethan(ethan_in_bound_config) => {
                assert_eq!(ethan_in_bound_config.port(), 10800);
                assert_eq!(ethan_in_bound_config.uid(), "ethan.wang");
                assert_eq!(ethan_in_bound_config.pwd(), "pass01!");
                match ethan_in_bound_config.tls() {
                    Some(tls_config) => {
                        assert_eq!(tls_config.crt_path, PathBuf::from("localhost.crt"));
                        assert_eq!(tls_config.key_path, PathBuf::from("localhost.key"));
                        assert_eq!(tls_config.domain_name, "localhost");
                    }
                    None => return Err("there should have an tls config".into()),
                }
            }
        }
        Ok(())
    }

    #[test]
    fn inbound_toml_socks_parse_test() -> Result<(), Box<dyn Error>> {
        let config_str = r#"
        protocol = "socks5"
        port = 1080
        
        "#;
        let config: InBoundTypeConfig = toml::from_str(config_str)?;
        match config {
            InBoundTypeConfig::Socks5(socks_in_bound_config) => {
                assert_eq!(socks_in_bound_config.port(), 1080);
                assert_eq!(socks_in_bound_config.pwd(), None);
                assert_eq!(socks_in_bound_config.uid(), None);
            }
            InBoundTypeConfig::Ethan(_) => {
                return Err("this is should be an socks5 config".into());
            }
        }
        Ok(())
    }
}
