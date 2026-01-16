use crate::{ethan::ethan_proto::ConnectRequest, traits::async_read_write::AsyncReadWrite};
use anyhow::Result;
use async_trait::async_trait;

#[async_trait]
pub(crate) trait OutBoundProxy: Send + Sync {
    async fn connect_server(&self, connect_request: ConnectRequest) -> Result<Box<dyn AsyncReadWrite+Unpin+Send>>;
}
