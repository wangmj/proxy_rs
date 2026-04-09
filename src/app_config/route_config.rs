use regex::Regex;
use serde_with::DeserializeFromStr;
use std::{
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    str::FromStr,
};

#[derive(Debug, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
pub struct RouteConfig {
    // #[serde(default)]
    // name: String,
    // #[serde(default)]
    // domain: Vec<String>,
    // #[serde(default)]
    // ip: Vec<String>,
    #[serde(default)]
    rule: String,
    #[serde(default)]
    proxy_name: String,
    rule_type: RuleType,
}
#[derive(Debug, serde::Serialize, PartialEq, Eq, DeserializeFromStr)]
#[serde(rename_all = "lowercase")]
pub enum RuleType {
    Regex,
    Wildcard,
    Domain,
    Ipv4,
    Ipv6,
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

        let domain_proxy = routes
            .iter()
            .filter(|x| x.is_match("www.google.com"))
            .next();
        assert!(domain_proxy.is_some());
        assert_eq!(domain_proxy.unwrap().proxy_name, "proxy_domain");

        let ipv4_proxy = routes.iter().filter(|x| x.is_match("192.168.5.10")).next();
        assert!(ipv4_proxy.is_some());
        assert_eq!(ipv4_proxy.unwrap().proxy_name(), "proxy_ipv4");

        // let ipv6_proxy=routes.iter().filter(|x|x.is_match("2001:0db8:85a3")).next();
        let reg_proxy = routes.iter().filter(|x| x.is_match("github.cn")).next();
        assert!(reg_proxy.is_some());
        assert_eq!(reg_proxy.unwrap().proxy_name(), "proxy_regex");

        let wild_proxy = routes.iter().filter(|x| x.is_match("cn.bing.com")).next();
        assert!(wild_proxy.is_some());
        assert_eq!(wild_proxy.unwrap().proxy_name(), "direct");
    }
}
