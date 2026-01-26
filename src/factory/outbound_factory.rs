use std::{ sync::Arc};

use crate::{
    OutputBoundTypeConfig, ethan::ethan_outbound::EthanOutBound, freedom::Freedom,
    traits::proxy_outbound::OutBoundProxy,
};

pub enum OutBoundType {
    Ethan,
    Freedom,
}
pub struct OutBoundFactory;
impl OutBoundFactory {
    pub(crate) fn get(t: &OutputBoundTypeConfig) -> Box<dyn OutBoundProxy> {
        match t {
            OutputBoundTypeConfig::Ethan(ethan_output_config) => {
                let config = Arc::new(ethan_output_config.clone());
                let ethan = EthanOutBound::new(config);
                Box::new(ethan) as Box<dyn OutBoundProxy>
            }
            OutputBoundTypeConfig::Freedom(_freedom_output_config) => Box::new(Freedom),
        }
    }
}
