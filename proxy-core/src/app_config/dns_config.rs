use std::str::FromStr;

use anyhow::anyhow;
use serde::Deserialize;
use serde_with::DeserializeFromStr;

#[derive(Debug, Deserialize, Clone, PartialEq)]
pub struct DnsConfig {
    pub resolver: DNSResolver,
    pub server: Option<Vec<String>>,
}
#[derive(Debug, Clone, PartialEq, DeserializeFromStr)]
pub enum DNSResolver {
    Local,
    Remote,
}

impl FromStr for DNSResolver {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "local" => Ok(Self::Local),
            "remote" => Ok(Self::Remote),
            _ => Err(anyhow!("unknown dns resolver")),
        }
    }
}


impl Default for DnsConfig{
    fn default() -> Self {
        Self { resolver: DNSResolver::Local, server: Default::default() }
    }
}