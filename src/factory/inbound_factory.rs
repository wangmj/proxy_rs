use std::{ops::Deref, sync::Arc};

use crate::{
    InBoundTypeConfig, dns_config::DnsConfig, ethan::ethan_inbound::EthanInBound, socks::socks5_inbound::Socks5InBound, traits::proxy_inbound::InBoundProxy
};

pub struct InBoundFactory;

impl InBoundFactory {
    pub async fn get(it: Arc<InBoundTypeConfig>,dns_conf:Arc<DnsConfig>) -> Box<dyn InBoundProxy> {
        match it.deref() {
            InBoundTypeConfig::Socks5(socks_in_bound_config) => {
                let cloned = socks_in_bound_config.clone();
                let dns_config=dns_conf.clone();
                Box::new(Socks5InBound::new(cloned.into(),dns_config)) as Box<dyn InBoundProxy>
            }
            InBoundTypeConfig::Ethan(ethan_in_bound_config) => {
                Box::new(EthanInBound::new(ethan_in_bound_config.clone().into()))
            }
        }
    }
}
