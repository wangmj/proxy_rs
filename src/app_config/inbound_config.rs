use std::path::PathBuf;

use serde::{
    Deserialize, Deserializer,
    de::{self, Error, Unexpected},
};

#[derive(Debug, serde::Deserialize, PartialEq)]
#[serde(untagged)] // 可选：避免枚举项的字段冲突，仅在枚举项有不同结构体字段时需要
pub enum InBoundTypeConfig {
    Socks5(SocksInBoundConfig),
    Ethan(EthanInBoundConfig),
}
#[derive(Debug, Clone, serde::Deserialize, PartialEq)]
pub struct SocksInBoundConfig {
    port: u16,
    dns: DnsConfig,
    uid: Option<String>,
    pwd: Option<String>,
}
impl SocksInBoundConfig {
    pub fn new(port: u16, uid: Option<String>, pwd: Option<String>, dns: DnsConfig) -> Self {
        Self {
            port,
            uid,
            pwd,
            dns,
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
    pub fn dns(&self) -> &DnsConfig {
        &self.dns
    }
}

#[derive(Debug, Deserialize, Clone, PartialEq)]
pub struct DnsConfig {
    pub resolver: DNSResolver,
    pub server: Option<Vec<String>>,
}
#[derive(Debug, Clone, PartialEq)]
pub enum DNSResolver {
    Local,
    Remote,
}

struct DnsResolverVisitor;
impl<'de> de::Visitor<'de> for DnsResolverVisitor {
    type Value = DNSResolver;

    fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(
            formatter,
            "a string representing of a dns resolver (local , remote)"
        )
    }
    fn visit_str<E>(self, v: &str) -> std::result::Result<Self::Value, E>
    where
        E: de::Error,
    {
        match v.trim().to_lowercase().as_str() {
            "local" => Ok(DNSResolver::Local),
            "remote" => Ok(DNSResolver::Remote),
            _ => Err(Error::invalid_type(Unexpected::Str(v), &self)),
        }
    }
}

impl<'de> Deserialize<'de> for DNSResolver {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_str(DnsResolverVisitor)
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

//输入的类型的中间结构体
#[derive(Debug, serde::Deserialize)]
struct InputBoundProtocolIntermediate {
    protocol: String,
    #[serde(flatten)] // 扁平化：将 TOML 中的其他字段直接解析到 config 中（避免嵌套）
    config: toml::Value, // 先以原始 Value 存储配置，后续再反序列化为具体结构体
}

// 自定义反序列化函数：核心逻辑——根据 protocol_type 映射枚举
pub(crate) fn deserialize_protocol<'de, D>(deserializer: D) -> Result<InBoundTypeConfig, D::Error>
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

    use crate::{DNSResolver, InBoundTypeConfig};

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
        dns.resolver = "local"
        dns.server = ["8.8.8.8"]
        "#;
        let config: InBoundTypeConfig = toml::from_str(config_str)?;
        match config {
            InBoundTypeConfig::Socks5(socks_in_bound_config) => {
                assert_eq!(socks_in_bound_config.port(), 1080);
                assert_eq!(socks_in_bound_config.pwd(), None);
                assert_eq!(socks_in_bound_config.uid(), None);
                assert_eq!(socks_in_bound_config.dns().resolver, DNSResolver::Local);
                assert_eq!(
                    socks_in_bound_config.dns().server,
                    Some(["8.8.8.8".into()].to_vec())
                );
            }
            InBoundTypeConfig::Ethan(_) => {
                return Err("this is should be an socks5 config".into());
            }
        }
        Ok(())
    }
}
