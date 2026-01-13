use crate::{
    app_config::InBoundTypeConfig, ethan_inbound::EthanInBound, socks5_inbound::Socks5InBound,
    traits::proxy_inbound::InBoundProxy,
};

pub struct InBoundFactory;

impl InBoundFactory {
    pub async fn get(it: &InBoundTypeConfig) -> Box<dyn InBoundProxy> {
        match it {
            InBoundTypeConfig::Socks5(socks_in_bound_config) => {
                let cloned = socks_in_bound_config.clone();
                Box::new(Socks5InBound::new(cloned.into())) as Box<dyn InBoundProxy>
            }
            InBoundTypeConfig::Ethan(ethan_in_bound_config) => {
                Box::new(EthanInBound::new(ethan_in_bound_config.clone().into()))
            }
        }
    }
}
