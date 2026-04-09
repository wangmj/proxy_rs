use super::inbound_config::*;
use super::outbound_config::*;
use anyhow::Result;
use anyhow::anyhow;
use clap::Parser;
use serde::{Deserialize, Deserializer};
use std::{env, net::IpAddr, path::Path, sync::LazyLock};

use crate::log_config::LogConfig;
use crate::route_config::RouteConfig;
use crate::{
    ethan::ethan_proto::{ConnectRequest, DstType},
    start_args::StartArgs,
};
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
    let config_content =
        std::fs::read_to_string(&config_path).expect("read config content failed!");
    AppConfig::parse_with_file_type(&config_content, &config_path)
        .expect("config format is incorrect.")
}

#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub struct AppConfig {
    log: LogConfig,
    #[serde(deserialize_with = "deserialize_protocol")]
    inbound: InBoundTypeConfig,
    #[serde(deserialize_with = "deserialize_outbounds")]
    outbounds: Vec<OutBoundTypeConfig>,
    #[serde(default)]
    routes: Vec<RouteConfig>,
}
impl AppConfig {
    pub fn parse_with_file_type(content: &str, config_path: &Path) -> Result<Self> {
        let ext = config_path
            .extension()
            .and_then(|x| x.to_str())
            .map(|x| x.to_ascii_lowercase());

        match ext.as_deref() {
            Some("json") => parse_json(content),
            Some("toml") => parse_toml(content),
            // Backward-compatible fallback for files with custom/no extension.
            _ => parse_toml(content),
        }
    }
    pub fn inbound(&self) -> &InBoundTypeConfig {
        &self.inbound
    }
    pub fn outbounds(&self) -> &[OutBoundTypeConfig] {
        &self.outbounds
    }

    pub fn log(&self) -> &LogConfig {
        &self.log
    }

    pub fn routes(&self) -> &[RouteConfig] {
        &self.routes
    }

    pub(crate) fn get_forward_to_remote(
        &self,
        connect_request: &ConnectRequest,
    ) -> Result<OutBoundTypeConfig> {
        // Keep backward compatibility: if no route rules are configured,
        // all requests still use the configured outbound.
        if self.routes.is_empty() {
            return Err(anyhow!("需要至少有一个路由选项"));
        }
        let target_addr = connect_request.dst_type().to_string();
        for r in &self.routes {
            if r.is_match(&target_addr) {
                return self
                    .outbounds()
                    .iter()
                    .find(|x| x.eq_name_ignore_case(r.proxy_name()))
                    .cloned()
                    .ok_or_else(|| {
                        anyhow!(format!("根据名称:{}没有找到匹配的项", r.proxy_name()))
                    });
            }
        }
        return Err(anyhow!("没有找到匹配的路由选项，需要配置一个任意都匹配的"));
    }
}

fn deserialize_outbounds<'de, D>(
    deserializer: D,
) -> std::result::Result<Vec<OutBoundTypeConfig>, D::Error>
where
    D: Deserializer<'de>,
{
    let values = Vec::<toml::Value>::deserialize(deserializer)?;
    values
        .into_iter()
        .map(parse_outbound_from_value)
        .collect::<std::result::Result<Vec<_>, _>>()
}

fn parse_outbound_from_value<E>(value: toml::Value) -> std::result::Result<OutBoundTypeConfig, E>
where
    E: serde::de::Error,
{
    let mut table = match value {
        toml::Value::Table(table) => table,
        _ => return Err(E::custom("outbound item must be table")),
    };
    let protocol = table
        .remove("protocol")
        .and_then(|x| x.as_str().map(|s| s.to_ascii_lowercase()))
        .ok_or_else(|| E::custom("missing outbound protocol"))?;
    let config_str = toml::to_string(&table).map_err(|e| E::custom(e.to_string()))?;
    match protocol.as_str() {
        "ethan" => {
            let cfg: EthanOutBoundConfig =
                toml::from_str(&config_str).map_err(|e| E::custom(e.to_string()))?;
            Ok(OutBoundTypeConfig::Ethan(cfg))
        }
        "freedom" => {
            let cfg: FreedomOutputConfig =
                toml::from_str(&config_str).map_err(|e| E::custom(e.to_string()))?;
            Ok(OutBoundTypeConfig::Freedom(cfg))
        }
        _ => Err(E::custom(format!(
            "unsupported outbound protocol: {}",
            protocol
        ))),
    }
}

fn parse_toml(content: &str) -> Result<AppConfig> {
    toml::from_str::<AppConfig>(content)
        .map_err(|e| anyhow!(format!("failed to parse config toml, err: {}", e)))
}

fn parse_json(content: &str) -> Result<AppConfig> {
    serde_json::from_str::<AppConfig>(content)
        .map_err(|e| anyhow!(format!("failed to parse json, err: {}", e)))
}

#[cfg(test)]
mod test {

    use std::{net::Ipv4Addr, path::PathBuf, str::FromStr};

    use super::*;
    use anyhow::Result;

    static TOML_CONFIG: &str = r##"
        [log]
        access.level = "info"
        access.path = "/tmp/access.log"

        [inbound]
        protocol = "socks5"
        port = 1080
        [inbound.dns]
        resolver = "local"
        server=["8.8.8.8"]

        [[outbounds]]
        name="ethan"
        protocol = "ethan"
        uid = "u"
        pwd = "p"
        port = 10800
        addr = "127.0.0.1"

        [outbounds.tls]
        use_tls = true
        domain_name="dev.ubuntu"
        crt_path="~/DevSpace/certs/dev.ubuntu.crt"

        [[outbounds]]
        name="freedom"
        protocol="freedom"

        [[routes]]
        proxy_name = "ethan"
        rule = "*.google.com"
        rule_type = "domain"

        [[routes]]
        proxy_name = "ethan"
        rule = "192.168.100.*"
        rule_type = "ipv4"

        [[routes]]
        proxy_name = "ethan"
        rule = "^github\\.$"
        rule_type = "regex"

        [[routes]]
        proxy_name = "freedom"
        rule = "*"
        rule_type = "wildcard"
        "##;

    #[test]
    fn app_config_fromstr_test() -> Result<()> {
        let appconfig = parse_toml(TOML_CONFIG)?;
        assert_eq!(
            appconfig.log.level().unwrap(),
            log::Level::from_str("info")?
        );
        assert_eq!(
            appconfig.log.access_path(),
            PathBuf::from("/tmp/access.log")
        );
        let dns_config = DnsConfig {
            resolver: DNSResolver::Local,
            server: Some(["8.8.8.8".into()].to_vec()),
        };
        let socks_input_config = SocksInBoundConfig::new(1080, None, None, dns_config);
        assert_eq!(
            appconfig.inbound,
            InBoundTypeConfig::Socks5(socks_input_config)
        );

        let ethan_output_config = EthanOutBoundConfig::new(
            "ethan".into(),
            "127.0.0.1".into(),
            10800,
            "u".into(),
            "p".into(),
            TlsClientConfig {
                use_tls: true,
                domain_name: Some("dev.ubuntu".into()),
                crt_path: Some("~/DevSpace/certs/dev.ubuntu.crt".into()),
            },
        );
        let freedom_output_config = FreedomOutputConfig::new("freedom");
        assert_eq!(
            appconfig.outbounds,
            [
                OutBoundTypeConfig::Ethan(ethan_output_config),
                OutBoundTypeConfig::Freedom(freedom_output_config)
            ]
        );

        Ok(())
    }

    const JSONCONIFG: &'static str = r##"
{
  "log": {
    "access": {
      "level": "info",
      "path": "/tmp/access.log"
    },
    "error": {
      "path": "/var/log/rs_proxy/error.log"
    }
  },
  "inbound": {
    "protocol": "socks5",
    "port": 1080,
    "dns":{
      "resolver":"local",
      "server":["8.8.8.8"]
    }
  },
  "outbounds": [
    {
      "name": "ethan",
      "protocol": "ethan",
      "uid": "u",
      "pwd": "p",
      "port": 10800,
      "addr": "127.0.0.1",
      "tls": {
        "use_tls": true,
        "domain_name": "dev.ubuntu",
        "crt_path": "~/DevSpace/certs/dev.ubuntu.crt"
      },
      "dns": {
        "resolver": "local",
        "server": [
          "8.8.8.8"
        ]
      }
    },
    {
      "name": "freedom",
      "protocol": "freedom"
    }
  ],
  "routes": [
    {
      "proxy_name": "ethan",
      "rule": "*.google.com",
      "rule_type": "Domain"
    },
    {
      "proxy_name": "ethan",
      "rule": "192.168.100.*",
      "rule_type": "Ipv4"
    },
    {
      "proxy_name": "ethan",
      "rule": "^github\\.$",
      "rule_type": "Regex"
    },
    {
      "proxy_name": "freedom",
      "rule": "*",
      "rule_type": "Wildcard"
    }
  ]
}"##;

    #[test]
    fn app_config_from_json_test() -> Result<()> {
        let appconfig = parse_json(JSONCONIFG)?;
        assert_eq!(
            appconfig.log.level().unwrap(),
            log::Level::from_str("info")?
        );
        assert_eq!(
            appconfig.log.access_path(),
            PathBuf::from("/tmp/access.log")
        );
        let dns_config = DnsConfig {
            resolver: DNSResolver::Local,
            server: Some(["8.8.8.8".into()].to_vec()),
        };
        let socks_input_config = SocksInBoundConfig::new(1080, None, None, dns_config);
        assert_eq!(
            appconfig.inbound,
            InBoundTypeConfig::Socks5(socks_input_config)
        );

        let ethan_output_config = EthanOutBoundConfig::new(
            "ethan".into(),
            "127.0.0.1".into(),
            10800,
            "u".into(),
            "p".into(),
            TlsClientConfig {
                use_tls: true,
                domain_name: Some("dev.ubuntu".into()),
                crt_path: Some("~/DevSpace/certs/dev.ubuntu.crt".into()),
            },
        );
        let freedom_output_config = FreedomOutputConfig::new("freedom");
        assert_eq!(
            appconfig.outbounds,
            [
                OutBoundTypeConfig::Ethan(ethan_output_config),
                OutBoundTypeConfig::Freedom(freedom_output_config)
            ]
        );

        assert_eq!(appconfig.routes().len(), 4);
        assert_eq!(
            appconfig.routes(),
            [
                RouteConfig::new(
                    "*.google.com",
                    "ethan",
                    crate::route_config::RuleType::Domain
                ),
                RouteConfig::new(
                    "192.168.100.*",
                    "ethan",
                    crate::route_config::RuleType::Ipv4
                ),
                RouteConfig::new("^github\\.$", "ethan", crate::route_config::RuleType::Regex),
                RouteConfig::new("*", "freedom", crate::route_config::RuleType::Wildcard),
            ]
        );
        Ok(())
    }

    #[test]
    fn get_outbound_config_test() -> Result<()> {
        let appconfig = parse_json(JSONCONIFG)?;
        let freedom_outbound_config =
            OutBoundTypeConfig::Freedom(FreedomOutputConfig::new("freedom"));

        let bing_request = ConnectRequest::new(1090, DstType::DomainName("cn.bing.com".into()));
        let get_outbound_config = appconfig.get_forward_to_remote(&bing_request)?;
        assert_eq!(get_outbound_config, freedom_outbound_config);

        let ipv4_request = ConnectRequest::new(
            443,
            DstType::Ipv4(Ipv4Addr::from_octets([192, 168, 100, 100])),
        );
        let get_outbound_config = appconfig.get_forward_to_remote(&ipv4_request)?;
        if let OutBoundTypeConfig::Ethan(ethan_config) = get_outbound_config {
            assert_eq!(ethan_config.name(), "ethan");
        } else {
            return Err(anyhow!("ipv4,should be ethan OutBoundType"));
        }

        let domain_request = ConnectRequest::new(443, DstType::DomainName("www.google.com".into()));
        let get_outbound_config = appconfig.get_forward_to_remote(&domain_request)?;
        if let OutBoundTypeConfig::Ethan(ethan_config) = get_outbound_config {
            assert_eq!(ethan_config.name(), "ethan");
        } else {
            return Err(anyhow!("google.com .should be ethan OutBoundType"));
        }
        Ok(())
    }
}
