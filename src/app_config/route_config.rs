use anyhow::anyhow;
use ipnetwork::IpNetwork;
use serde_with::DeserializeFromStr;
use std::{
    net::IpAddr,
    ops::Deref,
    str::{self, FromStr},
    sync::LazyLock,
};

use crate::{APP_CONFIG, dns_resolver, ethan::ethan_proto::DstType, geoip_helper::GEOIP_READER};

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


    pub(crate) async fn get_match(
        &self,
        dst: &DstType,
    ) -> &RouteConfig {
       let t= match dst {
            DstType::Ipv4(ip) => self.get_match_ip(&Into::<IpAddr>::into(*ip) ),
            DstType::Ipv6(ip) => self.get_match_ip(&Into::<IpAddr>::into(*ip)),
            DstType::DomainName(name) => {
                self.get_match_domain_name(name).await
            }
        };

       t.unwrap_or_else(||&DEFAULT_ROUTE_CONFIG)
    }
    fn get_match_ip(&self, ip: &IpAddr) -> Option<&RouteConfig> {
        self.0
            .iter()
            .filter(|&x| {
                x.rule_type() == &RuleType::Cidr
                    || x.rule_type() == &RuleType::GeoipCountry
                    || x.rule_type() == &RuleType::Geoipasn
            })
            .find(|x| x.is_match(ip.to_string()))
    }
    async fn get_match_domain_name(&self, name: impl AsRef<str>) -> Option<&RouteConfig> {
        let name = name.as_ref();
        let config = self
            .0
            .iter()
            .filter(|&x| *x.rule_type() == RuleType::Domain)
            .find(|&x| x.is_match(name));
        //如果没匹配，则检查是否在本地解析，
        //如果在本地解析，则解析该name对应的ip地址，再次进行匹配
        //否则，直接将匹配到默认规则
        match config {
            Some(config) => Some(config),
            None => match APP_CONFIG.dns().resolver {
                crate::dns_config::DNSResolver::Local => {
                    dns_resolver::resolve_dns_pick_fastet(name)
                        .await
                        .and_then(|ref ip| self.get_match_ip(ip).ok_or(anyhow!("aasdf")))
                        .ok()
                }
                crate::dns_config::DNSResolver::Remote => None,
            },
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
            "geoip:asn" | "geoip_asn" => Ok(Self::Geoipasn),
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
            if let Ok(country) = GEOIP_READER.get_country(&ip) {
                let country = country.trim();
                rule.split([',', ';'])
                    .map(|x| x.trim())
                    .any(|x| x.eq_ignore_ascii_case(country))
            } else {
                false
            }
        }
        Err(_) => false,
    }
}

fn match_geo_asn(target: &str, rule: &str) -> bool {
    match IpAddr::from_str(target) {
        Ok(ip) => match GEOIP_READER.get_asn(&ip) {
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

    #[tokio::test]
    #[ignore = "1.该测试依赖本地文件examples/config/client.toml中的配置，且当配置中的dns.resolver=local时，会触发在线的dns解析，耗时较长，因此仅在需要时测试"]
   async  fn routes_match() {
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
        let goole_dst_match = manager.get_match(&goole_dst).await;
        assert_eq!(goole_dst_match.to(), "proxy_goole");

        let ipv4_dst = DstType::Ipv4(Ipv4Addr::from_octets([192u8, 168, 5, 100]));
        let ipv4_dst_match = manager.get_match(&ipv4_dst).await;
        assert_eq!(ipv4_dst_match.to(), "proxy_cidr");

        let github_dst = DstType::DomainName("www.github.com".into());
        let github_dst_match = manager.get_match(&github_dst).await;
        assert_eq!(github_dst_match.to(), "proxy_github");

        let bing_dst = DstType::DomainName("www.baidu.com".into());
        let bing_dst_match = manager.get_match(&bing_dst).await;
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
