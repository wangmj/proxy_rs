use std::{
    net::{SocketAddr, SocketAddrV4, SocketAddrV6},
    pin::Pin,
};

use crate::{
    dns_resolver::resolve_dns_pick_fastet,
    ethan::ethan_proto::{ConnectRequest, DstType},
    traits::{async_read_write::AsyncReadWrite, proxy_outbound::OutBoundProxy},
};
use anyhow::Result;
use async_trait::async_trait;
use tokio::net::TcpStream;

pub struct Direct;

#[async_trait]
impl OutBoundProxy for Direct {
    async fn connect_server(
        &self,
        connect_request: ConnectRequest,
    ) -> Result<Pin<Box<dyn AsyncReadWrite>>> {
        let port = connect_request.port();
        let stream = match connect_request.dst_type() {
            DstType::Ipv4(ipv4_addr) => {
                TcpStream::connect(SocketAddrV4::new(*ipv4_addr, port)).await?
            }
            DstType::Ipv6(ipv6_addr) => {
                TcpStream::connect(SocketAddrV6::new(*ipv6_addr, port, 0, 0)).await?
            }
            DstType::DomainName(domain_name) => {
                let ipaddr = resolve_dns_pick_fastet(domain_name).await?;
                TcpStream::connect(SocketAddr::new(ipaddr, port)).await?
            }
        };
        Ok(Box::pin(stream))
    }
}
