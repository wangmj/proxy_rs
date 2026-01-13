use crate::ethan_proto::ConnectRequest;
use anyhow::Result;
use async_trait::async_trait;
use tokio::net::TcpStream;

#[async_trait]
pub(crate) trait OutBoundProxy: Send + Sync {
    async fn connect_server(&self, connect_request: ConnectRequest) -> Result<TcpStream>;
}
