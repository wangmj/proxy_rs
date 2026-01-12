use std::{net::SocketAddrV4, str::FromStr};

use crate::{ethan_client::EthanClient, ethan_proto::ConnectRequest, freedom::Freedom};
use anyhow::Result;
use async_trait::async_trait;
use tokio::net::TcpStream;

#[async_trait]
pub(crate) trait OutBoundClient: Send + Sync {
    async fn connect_server(&self, connect_request: ConnectRequest) -> Result<TcpStream>;
}

pub enum OutBoundType {
    Ethan,
    Freedom,
}
pub struct OutBoundFactory;
impl OutBoundFactory {
    pub(crate) fn get(t: OutBoundType) -> Box<dyn OutBoundClient> {
        match t {
            OutBoundType::Ethan => {
                let addr =
                    SocketAddrV4::from_str("127.0.0.1:10800").expect("convert to addr failed!");
                Box::new(EthanClient::new(addr.into()))
            }
            OutBoundType::Freedom => Box::new(Freedom),
        }
    }
}
