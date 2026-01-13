use std::{net::SocketAddrV4, str::FromStr};

use crate::{
    ethan_outbound::EthanOutBound, freedom::Freedom, traits::proxy_outbound::OutBoundProxy,
};

pub enum OutBoundType {
    Ethan,
    Freedom,
}
pub struct OutBoundFactory;
impl OutBoundFactory {
    pub(crate) fn get(t: OutBoundType) -> Box<dyn OutBoundProxy> {
        match t {
            OutBoundType::Ethan => {
                let addr =
                    SocketAddrV4::from_str("127.0.0.1:10800").expect("convert to addr failed!");
                Box::new(EthanOutBound::new(addr.into()))
            }
            OutBoundType::Freedom => Box::new(Freedom),
        }
    }
}
