use super::inbound_config::*;
use super::outbound_config::*;
use anyhow::Result;
use anyhow::anyhow;
use clap::Parser;
use std::{env, path::Path, sync::LazyLock};

use crate::log_config::LogConfig;
use crate::route_config::RouteManager;
use crate::{ethan::ethan_proto::ConnectRequest, start_args::StartArgs};
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
    AppConfig::open_readfile(config_path).expect("read config failed!")
}

#[derive(Debug, serde::Deserialize)]
pub struct AppConfig {
    log: LogConfig,
    #[serde(deserialize_with = "deserialize_protocol")]
    inbound: InBoundTypeConfig,
    // #[serde(deserialize_with = "deserialize_outbounds")]
    outbounds: Vec<OutBoundTypeConfig>,
    // #[serde(default)]
    routes: RouteManager,
}
impl AppConfig {
    pub fn open_readfile(config_path: impl AsRef<Path>) -> Result<Self> {
        let config_path = config_path.as_ref();
        let ext = config_path
            .extension()
            .and_then(|x| x.to_str())
            .map(|x| x.to_ascii_lowercase());

        let config_content: String = std::fs::read_to_string(&config_path)?;

        match ext.as_deref() {
            Some("json") => parse_json(&config_content),
            Some("toml") => parse_toml(&config_content),
            // Backward-compatible fallback for files with custom/no extension.
            _ => parse_toml(&config_content),
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

    pub fn routes(&self) -> &RouteManager {
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
        let target_dst_type = connect_request.dst_type();
        let route = self.routes().get_match(target_dst_type);
        self.outbounds()
            .iter()
            .find(|x| x.eq_name_ignore_case(route.to()))
            .cloned()
            .ok_or_else(|| anyhow!(format!("根据名称:{}没有找到匹配的项", route.to())))
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

    use crate::{
        ethan::ethan_proto::DstType,
        route_config::{RouteConfig, RuleType},
    };

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
        name="proxy"
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
        name="direct"
        protocol="direct"

        [[routes]]
        to = "direct"
        rule = "127.0.0.0/8,10.0.0.0/8,172.16.0.0/12,192.168.0.0/16,169.254.0.0/16"
        rule_type = "CIDR"

        [[routes]]
        to = "direct"
        rule = "CN"
        rule_type = "GeoIP:country"

        [[routes]]
        to = "direct"
        rule = "AS4134,AS4837,AS9808,AS24153,AS37963,AS45090,AS136907,AS38355,AS55967"
        rule_type = "GeoIP:asn"

        [[routes]]
        to = "proxy"
        rule = "*"
        rule_type = "default"
        "##;

    #[test]
    fn app_config_parse_toml_test() -> Result<()> {
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
            "proxy".into(),
            "127.0.0.1".into(),
            10800,
            "u".into(),
            "p".into(),
            Some(TlsClientConfig {
                use_tls: true,
                domain_name: "dev.ubuntu".into(),
                crt_path: "~/DevSpace/certs/dev.ubuntu.crt".into(),
            }),
        );
        let direct_output_config = DirectOutputConfig::new("direct");
        assert_eq!(
            appconfig.outbounds,
            [
                OutBoundTypeConfig::Ethan(ethan_output_config),
                OutBoundTypeConfig::Direct(direct_output_config)
            ]
        );
        assert_eq!(appconfig.routes().len(), 4);

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
      "name": "proxy",
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
      "name": "direct",
      "protocol": "direct"
    }
  ],
  "routes": [
     {
      "to": "direct",
      "rule": "127.0.0.0/8,10.0.0.0/8,172.16.0.0/12,192.168.0.0/16,169.254.0.0/16",
      "rule_type": "CIDR"
    },
    {
      "to": "direct",
      "rule": "CN",
      "rule_type": "GeoIP:country"
    },
    {
      "to": "direct",
      "rule": "AS4134,AS4837,AS9808,AS24153,AS37963,AS45090,AS136907,AS38355,AS55967",
      "rule_type": "GeoIP:asn"
    },
    {
      "to":"proxy",
      "rule":"*",
      "rule_type":"default"
    }
  ]
}"##;

    #[test]
    fn app_config_parse_json_test() -> Result<()> {
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
            "proxy".into(),
            "127.0.0.1".into(),
            10800,
            "u".into(),
            "p".into(),
            Some(TlsClientConfig {
                use_tls: true,
                domain_name: "dev.ubuntu".into(),
                crt_path: "~/DevSpace/certs/dev.ubuntu.crt".into(),
            }),
        );
        let direct_output_config = DirectOutputConfig::new("direct");
        assert_eq!(
            appconfig.outbounds,
            [
                OutBoundTypeConfig::Ethan(ethan_output_config),
                OutBoundTypeConfig::Direct(direct_output_config)
            ]
        );

        assert_eq!(appconfig.routes().len(), 4);
        assert_eq!(
            appconfig.routes(),
            &RouteManager::new([
                RouteConfig::new(
                    "127.0.0.0/8,10.0.0.0/8,172.16.0.0/12,192.168.0.0/16,169.254.0.0/16",
                    "direct",
                    RuleType::Cidr
                ),
                RouteConfig::new("CN", "direct", RuleType::GeoipCountry),
                RouteConfig::new(
                    "AS4134,AS4837,AS9808,AS24153,AS37963,AS45090,AS136907,AS38355,AS55967",
                    "direct",
                    RuleType::Geoipasn
                ),
                RouteConfig::new("*", "proxy", RuleType::Default),
            ])
        );
        Ok(())
    }

    #[test]
    fn appconfig_get_outbound_test() -> Result<()> {
        let appconfig = parse_json(JSONCONIFG)?;
        let direct_outbound_config = OutBoundTypeConfig::Direct(DirectOutputConfig::new("direct"));

        let baidu_request = ConnectRequest::new(443, DstType::DomainName("www.baidu.com".into()));
        let get_outbound_config: OutBoundTypeConfig =
            appconfig.get_forward_to_remote(&baidu_request)?;
        assert_eq!(get_outbound_config, direct_outbound_config);

        let ipv4_request = ConnectRequest::new(
            443,
            DstType::Ipv4(Ipv4Addr::from_octets([192, 168, 100, 100])),
        );
        let get_outbound_config = appconfig.get_forward_to_remote(&ipv4_request)?;
        if let OutBoundTypeConfig::Direct(_direct) = get_outbound_config {
        } else {
            return Err(anyhow!("local ip should be a direct route"));
        }

        let domain_request = ConnectRequest::new(443, DstType::DomainName("www.google.com".into()));
        let get_outbound_config = appconfig.get_forward_to_remote(&domain_request)?;
        if let OutBoundTypeConfig::Ethan(ethan_config) = get_outbound_config {
            assert_eq!(ethan_config.name(), "proxy");
        } else {
            return Err(anyhow!("google.com .should be ethan OutBoundType"));
        }
        Ok(())
    }

    #[test]
    fn example_config_load_test() -> Result<()> {
        let mut base_dir = env::current_dir()?;
        base_dir.push("examples/config");
        let client_json_file = base_dir.join("client.json");
        let client_toml_file = base_dir.join("client.toml");
        let server_json_file = base_dir.join("server.json");
        let server_toml_file = base_dir.join("server.toml");

        let _ = AppConfig::open_readfile(client_json_file)?;
        println!("client json file correct!");
        let _ = AppConfig::open_readfile(client_toml_file)?;
        println!("client toml file correct!");
        let _ = AppConfig::open_readfile(server_json_file)?;
        println!("server json file correct!");
        let _ = AppConfig::open_readfile(server_toml_file)?;
        println!("server json file correct!");
        Ok(())

    }
}
