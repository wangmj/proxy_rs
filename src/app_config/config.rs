use super::inbound_config::*;
use super::outbound_config::*;
use anyhow::Result;
use clap::Parser;
use regex::Regex;
use std::{
    env,
    net::IpAddr,
    path::{Path, PathBuf},
    str::FromStr,
    sync::LazyLock,
};

use crate::{ethan::ethan_proto::{ConnectRequest, DstType}, start_args::StartArgs};
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
    #[serde(deserialize_with = "deserialize_output_protocol")]
    outbound: OutputBoundTypeConfig,
    #[serde(default)]
    route: RouteConfig,
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

    pub fn route(&self) -> &RouteConfig {
        &self.route
    }

    pub(crate) fn should_forward_to_remote(&self, connect_request: &ConnectRequest) -> bool {
        // Keep backward compatibility: if no route rules are configured,
        // all requests still use the configured outbound.
        if self.route.is_empty() {
            return true;
        }

        match connect_request.dst_type() {
            DstType::DomainName(domain) => self.route.matches_domain(domain),
            DstType::Ipv4(ipv4) => self.route.matches_ip(IpAddr::V4(*ipv4)),
            DstType::Ipv6(ipv6) => self.route.matches_ip(IpAddr::V6(*ipv6)),
        }
    }
}

#[derive(Debug, serde::Serialize, serde::Deserialize, Default)]
pub struct RouteConfig {
    #[serde(default)]
    domain: Vec<String>,
    #[serde(default)]
    ip: Vec<String>,
}

impl RouteConfig {
    pub fn is_empty(&self) -> bool {
        self.domain.is_empty() && self.ip.is_empty()
    }

    fn matches_domain(&self, domain: &str) -> bool {
        let target = normalize_domain(domain);
        self.domain
            .iter()
            .any(|rule| match_regex_rule(&target, rule, "route.domain"))
    }

    fn matches_ip(&self, ip: IpAddr) -> bool {
        let target = ip.to_string();
        self.ip
            .iter()
            .any(|rule| match_regex_rule(&target, rule, "route.ip"))
    }
}

fn normalize_domain(val: &str) -> String {
    val.trim().trim_end_matches('.').to_ascii_lowercase()
}

fn match_regex_rule(target: &str, rule: &str, rule_group: &str) -> bool {
    let trimmed = rule.trim();
    if trimmed.is_empty() {
        return false;
    }

    match Regex::new(trimmed) {
        Ok(regex) => regex.is_match(target),
        Err(err) => {
            log::warn!("invalid {} regex ignored: {}, error: {}", rule_group, trimmed, err);
            false
        }
    }
}

impl FromStr for AppConfig {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        let f: AppConfig = toml::from_str(s)?;
        Ok(f)
    }
}

impl AppConfig {
    fn parse_with_file_type(content: &str, config_path: &Path) -> Result<Self> {
        let ext = config_path
            .extension()
            .and_then(|x| x.to_str())
            .map(|x| x.to_ascii_lowercase());

        match ext.as_deref() {
            Some("json") => parse_json_or_toml(content),
            Some("toml") => parse_toml_or_json(content),
            // Backward-compatible fallback for files with custom/no extension.
            _ => parse_toml_or_json(content),
        }
    }
}

fn parse_toml_or_json(content: &str) -> Result<AppConfig> {
    match toml::from_str::<AppConfig>(content) {
        Ok(cfg) => Ok(cfg),
        Err(toml_err) => match serde_json::from_str::<AppConfig>(content) {
            Ok(cfg) => Ok(cfg),
            Err(json_err) => Err(anyhow::anyhow!(
                "failed to parse config as TOML or JSON; toml_err: {}; json_err: {}",
                toml_err,
                json_err
            )),
        },
    }
}

fn parse_json_or_toml(content: &str) -> Result<AppConfig> {
    match serde_json::from_str::<AppConfig>(content) {
        Ok(cfg) => Ok(cfg),
        Err(json_err) => match toml::from_str::<AppConfig>(content) {
            Ok(cfg) => Ok(cfg),
            Err(toml_err) => Err(anyhow::anyhow!(
                "failed to parse config as JSON or TOML; json_err: {}; toml_err: {}",
                json_err,
                toml_err
            )),
        },
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
        access.path = "log/access.log"
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
        use_tls = true
        domain_name = "dev.ubuntu"
        crt_path = "~/DevSpace/certs/dev.ubuntu.crt"

        [outbound.dns]
        resolver = "local"
        server = ["8.8.8.8"]

        [route]
        domain = ["(^|\\.)google\\.com$", "^github\\.com$"]
        ip = ["^1\\.1\\.1\\.1$", "^8\\.8\\.8\\.[0-9]{1,3}$"]

"##;
        let appconfig = AppConfig::from_str(config)?;
        assert_eq!(appconfig.log.access.level, "trace");
        assert_eq!(
            appconfig.log.access.path,
            PathBuf::from("log/access.log")
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
                domain_name: Some("dev.ubuntu".into()),
                crt_path: Some("~/DevSpace/certs/dev.ubuntu.crt".into()),
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
        assert!(appconfig.route.matches_domain("www.google.com"));
        assert!(appconfig.route.matches_ip("8.8.8.8".parse()?));
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

    #[test]
    fn route_match_test() -> Result<()> {
        let str = r##"
        [log]
        access.level = "info"
        access.path = "/tmp/access.log"

        [inbound]
        protocol = "socks5"
        port = 1080

        [outbound]
        protocol = "ethan"
        uid = "u"
        pwd = "p"
        port = 10800
        addr = "127.0.0.1"

        [outbound.tls]
        use_tls = false

        [outbound.dns]
        resolver = "local"

        [route]
        domain = ["(^|\\.)example\\.com$", "^api\\.test\\.com$"]
        ip = ["^10\\..*", "^2001:db8:.*", "^127\\.0\\.0\\.1$"]
        "##;

        let appconfig = AppConfig::from_str(str)?;

        let req1 = ConnectRequest::new(443, DstType::DomainName("www.example.com".into()));
        assert!(appconfig.should_forward_to_remote(&req1));

        let req2 = ConnectRequest::new(443, DstType::DomainName("no-match.com".into()));
        assert!(!appconfig.should_forward_to_remote(&req2));

        let req3 = ConnectRequest::new(80, DstType::Ipv4("10.2.3.4".parse()?));
        assert!(appconfig.should_forward_to_remote(&req3));

        let req4 = ConnectRequest::new(80, DstType::Ipv4("11.2.3.4".parse()?));
        assert!(!appconfig.should_forward_to_remote(&req4));

        Ok(())
    }

        #[test]
        fn app_config_from_json_test() -> Result<()> {
                let json = r##"
                {
                    "log": {
                        "access": {
                            "level": "info",
                            "path": "log/access.log"
                        }
                    },
                    "inbound": {
                        "protocol": "socks5",
                        "port": 1080
                    },
                    "outbound": {
                        "protocol": "ethan",
                        "uid": "ethan.wang",
                        "pwd": "pass01!",
                        "port": 10800,
                        "addr": "127.0.0.1",
                        "tls": {
                            "use_tls": false
                        },
                        "dns": {
                            "resolver": "local",
                            "server": ["8.8.8.8"]
                        }
                    },
                    "route": {
                        "domain": ["(^|\\.)example\\.com$"],
                        "ip": ["^10\\..*"]
                    }
                }
                "##;

                let appconfig = parse_json_or_toml(json)?;
                let req_domain = ConnectRequest::new(443, DstType::DomainName("www.example.com".into()));
                let req_ip = ConnectRequest::new(80, DstType::Ipv4("10.1.2.3".parse()?));
                assert!(appconfig.should_forward_to_remote(&req_domain));
                assert!(appconfig.should_forward_to_remote(&req_ip));
                Ok(())
        }
}
