use std::{ sync::Arc};

use crate::{
    OutBoundTypeConfig, ethan::ethan_outbound::EthanOutBound, direct::Direct,
    traits::proxy_outbound::OutBoundProxy,
};

pub enum OutBoundType {
    Ethan,
    Direct,
}
pub struct OutBoundFactory;
impl OutBoundFactory {
    pub(crate) fn get(t: &OutBoundTypeConfig) -> Box<dyn OutBoundProxy> {
        match t {
            OutBoundTypeConfig::Ethan(ethan_output_config) => {
                let config = Arc::new(ethan_output_config.clone());
                let ethan = EthanOutBound::new(config);
                Box::new(ethan) as Box<dyn OutBoundProxy>
            }
            OutBoundTypeConfig::Direct(_) => Box::new(Direct),
        }
    }
}
