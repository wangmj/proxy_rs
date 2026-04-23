use regex::Regex;
use serde_with::DeserializeFromStr;
use std::{
    net::{Ipv4Addr, Ipv6Addr},
    str::FromStr,
};

use crate::ethan::ethan_proto::DstType;

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
        if !self.0.iter().any(|x| x.rule_type() == &RuleType::Wildcard) {
            self.0.push(RouteConfig {
                rule: "".into(),
                proxy_name: "default_wild_pattern".into(),
                rule_type: RuleType::Wildcard,
            });
        }
    }

    pub(crate) fn get_match(&self, dst: &DstType) -> &RouteConfig {
        let proxy_name;
        match dst {
            DstType::Ipv4(ipv4_addr) => {
                proxy_name = self
                    .0
                    .iter()
                    .filter(|x| {
                        x.rule_type() == &RuleType::Ipv4 || x.rule_type() == &RuleType::Regex
                    })
                    .find(|&x| x.is_match(ipv4_addr.to_string()));
            }
            DstType::Ipv6(ipv6_addr) => {
                proxy_name = self
                    .0
                    .iter()
                    .filter(|x| {
                        x.rule_type() == &RuleType::Ipv6 || x.rule_type() == &RuleType::Regex
                    })
                    .find(|&x| x.is_match(ipv6_addr.to_string()));
            }
            DstType::DomainName(name) => {
                proxy_name = self
                    .0
                    .iter()
                    .filter(|x| {
                        x.rule_type() == &RuleType::Domain || x.rule_type() == &RuleType::Regex
                    })
                    .find(|x| x.is_match(name));
            }
        }
        match proxy_name {
            Some(rc) => rc,
            None => self
                .0
                .iter()
                .find(|x| x.rule_type() == &RuleType::Wildcard)
                .unwrap(),
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
#[derive(Debug, serde::Deserialize, PartialEq, Eq)]
pub struct RouteConfig {
    #[serde(default)]
    rule: String,
    #[serde(default)]
    proxy_name: String,
    rule_type: RuleType,
}
#[derive(Debug, PartialEq, Eq, DeserializeFromStr)]
pub enum RuleType {
    Regex = 0,
    Wildcard = 1,
    Domain = 2,
    Ipv4 = 3,
    Ipv6 = 4,
}

impl RouteConfig {
    pub fn new(
        rule: impl Into<String>,
        proxy_name: impl Into<String>,
        route_type: RuleType,
    ) -> Self {
        Self {
            rule: rule.into(),
            proxy_name: proxy_name.into(),
            rule_type: route_type,
        }
    }
    pub fn proxy_name(&self) -> &str {
        &self.proxy_name
    }
    pub fn rule_type(&self) -> &RuleType {
        &self.rule_type
    }
    pub fn is_match(&self, s: impl AsRef<str>) -> bool {
        let s = s.as_ref();
        match self.rule_type {
            RuleType::Wildcard => true,
            RuleType::Regex => match_regex(s, &self.rule),
            RuleType::Domain => match_domain(s, &self.rule),
            RuleType::Ipv4 => match_ipv4(s, &self.rule),
            RuleType::Ipv6 => match_ipv6(s, &self.rule),
        }
    }
}

impl FromStr for RuleType {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "domain" => Ok(Self::Domain),
            "ipv4" => Ok(Self::Ipv4),
            "ipv6" => Ok(Self::Ipv6),
            "regex" => Ok(Self::Regex),
            "wildcard" => Ok(Self::Wildcard),
            _ => Err(format!("无效规则类型: {}", s)),
        }
    }
}

fn match_regex(target: &str, rule: &str) -> bool {
    let trimmed = rule.trim();
    if trimmed.is_empty() {
        return false;
    }

    match Regex::new(trimmed) {
        Ok(regex) => regex.is_match(target),
        Err(err) => {
            log::warn!("invalid {} regex, error: {}", trimmed, err);
            false
        }
    }
}

fn match_ipv4(target: &str, rule: &str) -> bool {
    if let Ok(target_ip) = Ipv4Addr::from_str(target) {
        let target_vec = target_ip.octets().map(|x| x.to_string());
        let rule_vec: Vec<_> = rule.split(".").collect();
        for i in 0..4 {
            if target_vec[i].ne(rule_vec[i]) && rule_vec[i] != "*" {
                return false;
            }
        }
        true
    } else {
        false
    }
}
fn match_ipv6(target: &str, rule: &str) -> bool {
    if let Ok(target_ipv6) = Ipv6Addr::from_str(target) {
        let target_vec = target_ipv6.octets().map(|x| x.to_string());
        let rule_vec: Vec<_> = rule.trim().split(":").collect();
        for i in 0..target_vec.len() {
            if target_vec[i].ne(rule_vec[i]) && rule_vec[i] != "*" {
                return false;
            }
        }
        true
    } else {
        false
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

    use anyhow::Result;

    use super::*;

    #[test]
    fn routes_match() {
        let mut routes = Vec::new();
        routes.push(RouteConfig::new(
            "*.google.com",
            "proxy_domain",
            RuleType::Domain,
        ));
        routes.push(RouteConfig::new(
            "192.168.*.*",
            "proxy_ipv4",
            RuleType::Ipv4,
        ));
        routes.push(RouteConfig::new(
            "2001:0db8:85a3:0000:0000:8a2e:0370:7334",
            "proxy_ipv6",
            RuleType::Ipv6,
        ));
        routes.push(RouteConfig::new(
            "^github\\..*$",
            "proxy_regex",
            RuleType::Regex,
        ));
        routes.push(RouteConfig::new("*", "direct", RuleType::Wildcard));
        let manager = RouteManager::from(routes);

        let goole_dst = DstType::DomainName("www.google.com".into());
        let goole_dst_match = manager.get_match(&goole_dst);
        assert_eq!(goole_dst_match.proxy_name(), "proxy_domain");

        let ipv4_dst = DstType::Ipv4(Ipv4Addr::from_octets([192u8, 168, 5, 100]));
        let ipv4_dst_match = manager.get_match(&ipv4_dst);
        assert_eq!(ipv4_dst_match.proxy_name(), "proxy_ipv4");

        let github_dst = DstType::DomainName("github.com".into());
        let github_dst_match = manager.get_match(&github_dst);
        assert_eq!(github_dst_match.proxy_name(), "proxy_regex");

        let bing_dst = DstType::DomainName("cn.bing.com".into());
        let bing_dst_match = manager.get_match(&bing_dst);
        assert_eq!(bing_dst_match.proxy_name(), "direct");
    }

    #[test]
    fn toml_parse_test() -> Result<()> {
        let content = r#"
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
                RouteConfig::new("*.google.com", "ethan", RuleType::Domain),
                RouteConfig::new("192.168.100.*", "ethan", RuleType::Ipv4),
                RouteConfig::new("^github\\.$", "ethan", RuleType::Regex),
                RouteConfig::new("*", "freedom", RuleType::Wildcard),
            ])
        );

        Ok(())
    }
}
