use ipnetwork::IpNetwork;
use serde_with::DeserializeFromStr;
use std::{
    net::IpAddr,
    ops::Deref,
    str::{self, FromStr},
    sync::LazyLock,
};

use crate::{dns_resolver, ethan::ethan_proto::DstType, geoip_helper};

static DEFAULT_ROUTE_CONFIG: LazyLock<RouteConfig> =
    LazyLock::new(|| RouteConfig::new("*".to_string(), "Direct", RuleType::Default));


#[derive(Debug, PartialEq, Eq, serde::Deserialize)]
#[serde(transparent)]
pub struct RouteManager(Vec<RouteConfig>);
impl RouteManager {
    pub fn new(routes: impl IntoIterator<Item = RouteConfig>) -> Self {
        let mut s = Self(routes.into_iter().collect());
        s.normalize();
        s
    }
    //归一化，添加必须的*通配符
    fn normalize(&mut self) {
        if !self.0.iter().any(|x| x.rule_type() == &RuleType::Default) {
            self.0.push(DEFAULT_ROUTE_CONFIG.deref().clone());
        }
    }

    pub(crate) fn get_match(&self, dst: &DstType) -> &RouteConfig {
        match dst {
            DstType::Ipv4(ip) => {
                let config = self
                    .0
                    .iter()
                    .filter(|&x| {
                        x.rule_type() == &RuleType::Cidr
                            || x.rule_type() == &RuleType::GeoipCountry
                            || x.rule_type() == &RuleType::Geoipasn
                    })
                    .find(|x| x.is_match(ip.to_string()));
                
                match config {
                    Some(config) => config,
                    None => self
                        .0
                        .iter()
                        .find(|&x| x.rule_type() == &RuleType::Default)
                        .unwrap_or_else(|| &DEFAULT_ROUTE_CONFIG),
                }
            }
            DstType::Ipv6(ip) => {
                let config = self
                    .0
                    .iter()
                    .filter(|&x| {
                        x.rule_type() == &RuleType::Cidr
                            || x.rule_type() == &RuleType::GeoipCountry
                            || x.rule_type() == &RuleType::Geoipasn
                    })
                    .find(|x| x.is_match(ip.to_string()));
                match config {
                    Some(config) => config,
                    None => self
                        .0
                        .iter()
                        .find(|&x| x.rule_type() == &RuleType::Default)
                        .unwrap_or_else(|| DEFAULT_ROUTE_CONFIG.deref()),
                }
            }

            DstType::DomainName(name) => {
                let config = self
                    .0
                    .iter()
                    .filter(|&x| *x.rule_type() == RuleType::Domain)
                    .find(|&x| x.is_match(name));
                //如果没匹配，则解析该name对应的ip地址，再次进行匹配
                match config {
                    Some(config) => config,
                    None => match dns_resolver::resolve_dns_pick_fastet(name) {
                        Ok(ip) => match ip {
                            IpAddr::V4(ipv4_addr) => self.get_match(&DstType::Ipv4(ipv4_addr)),
                            IpAddr::V6(ipv6_addr) => self.get_match(&DstType::Ipv6(ipv6_addr)),
                        },
                        Err(err) => {
                            log::warn!("在本地解析域名时失败，将直接转发direct,err:{err}");
                            DEFAULT_ROUTE_CONFIG.deref()
                        }
                    },
                }
            }
        }
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
    pub fn len(&self) -> usize {
        self.0.len()
    }
}

impl<T> From<T> for RouteManager
where
    T: IntoIterator<Item = RouteConfig>,
{
    fn from(value: T) -> Self {
        Self::new(value)
    }
}
#[derive(Debug, serde::Deserialize, PartialEq, Eq, Clone)]
pub struct RouteConfig {
    #[serde(default)]
    rule: String,
    #[serde(default)]
    to: String,
    rule_type: RuleType,
}
#[derive(Debug, PartialEq, Eq, DeserializeFromStr, Clone)]
pub enum RuleType {
    Cidr,
    Geoipasn,
    GeoipCountry,
    Domain,
    Default,
}

impl RouteConfig {
    pub fn new(rule: impl Into<String>, to: impl Into<String>, route_type: RuleType) -> Self {
        Self {
            rule: rule.into(),
            to: to.into(),
            rule_type: route_type,
        }
    }
    pub fn to(&self) -> &str {
        &self.to
    }
    pub fn rule_type(&self) -> &RuleType {
        &self.rule_type
    }
    pub fn is_match(&self, s: impl AsRef<str>) -> bool {
        let s = s.as_ref();
        match self.rule_type {
            RuleType::Default => true,
            RuleType::Cidr => match_cidr(s, &self.rule),
            RuleType::Domain => match_domain(s, &self.rule),
            RuleType::GeoipCountry => match_geoip_country(s, &self.rule),
            RuleType::Geoipasn => match_geo_asn(s, &self.rule),
        }
    }
}

impl FromStr for RuleType {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "domain" => Ok(Self::Domain),
            "cidr" => Ok(Self::Cidr),
            "geoip:country" | "geoip_country" => Ok(Self::GeoipCountry),
            "geoip:asn"|"geoip_asn" => Ok(Self::Geoipasn),
            "default" => Ok(Self::Default),
            _ => Err(format!("无效规则类型: {}", s)),
        }
    }
}

fn match_cidr(target: &str, rule: &str) -> bool {
    match IpAddr::from_str(target) {
        Ok(ip) => {
            //不合规的会被跳过
            rule.split([',', ';'])
                .map_while(|x| IpNetwork::from_str(x).ok())
                .any(|x| x.contains(ip))
        }
        Err(_) => false,
    }
}

fn match_geoip_country(target: &str, rule: &str) -> bool {
    match IpAddr::from_str(target) {
        Ok(ip) => {
            if let Ok(country) = geoip_helper::get_country(&ip) {
                let country = country.trim();
                rule.split([',', ';'])
                    .map(|x| x.trim())
                    .any(|x| x.eq_ignore_ascii_case(&country))
            } else {
                false
            }
        }
        Err(_) => false,
    }
}

fn match_geo_asn(target: &str, rule: &str) -> bool {
    match IpAddr::from_str(target) {
        Ok(ip) => match geoip_helper::get_asn(&ip) {
            Ok(asn) => {
                let asn = asn.trim();
                rule.split([',', ';'])
                    .map(|x| x.trim())
                    .any(|x| x.eq_ignore_ascii_case(asn))
            }
            Err(_) => false,
        },
        Err(_) => false,
    }
}

fn match_domain(target: &str, rule: &str) -> bool {
    if rule.starts_with("*") {
        let suffix = rule.replace("*", "");
        target.ends_with(&suffix)
    } else {
        target == rule
    }
}
#[cfg(test)]
mod test {

    use std::net::Ipv4Addr;

    use anyhow::Result;

    use super::*;

    #[test]
    fn routes_match() {
        let mut routes = Vec::new();
        routes.push(RouteConfig::new(
            "*.google.com",
            "proxy_goole",
            RuleType::Domain,
        ));
        routes.push(RouteConfig::new(
            "192.168.0.0/8",
            "proxy_cidr",
            RuleType::Cidr,
        ));
        routes.push(RouteConfig::new(
            "169.254.0.0/16",
            "proxy_cidr",
            RuleType::Cidr,
        ));

        routes.push(RouteConfig::new("CN", "direct", RuleType::GeoipCountry));
        routes.push(RouteConfig::new(
            "*.github.com",
            "proxy_github",
            RuleType::Domain,
        ));
        routes.push(RouteConfig::new("*", "direct", RuleType::Default));

        let manager = RouteManager::from(routes);

        let goole_dst = DstType::DomainName("www.google.com".into());
        let goole_dst_match = manager.get_match(&goole_dst);
        assert_eq!(goole_dst_match.to(), "proxy_goole");

        let ipv4_dst = DstType::Ipv4(Ipv4Addr::from_octets([192u8, 168, 5, 100]));
        let ipv4_dst_match = manager.get_match(&ipv4_dst);
        assert_eq!(ipv4_dst_match.to(), "proxy_cidr");

        let github_dst = DstType::DomainName("www.github.com".into());
        let github_dst_match = manager.get_match(&github_dst);
        assert_eq!(github_dst_match.to(), "proxy_github");

        let bing_dst = DstType::DomainName("www.baidu.com".into());
        let bing_dst_match = manager.get_match(&bing_dst);
        assert_eq!(bing_dst_match.to(), "direct");
    }

    #[test]
    fn toml_parse_test() -> Result<()> {
        let content = r#"
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
        "#;

        let value: toml::Value = toml::from_str(content)?;
        let manager: RouteManager = value
            .get("routes")
            .cloned()
            .ok_or_else(|| anyhow::anyhow!("missing routes field in toml test content"))?
            .try_into()?;

        assert_eq!(
            manager,
            RouteManager::new([
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
}
