use std::pin::Pin;

use crate::{ethan::ethan_proto::ConnectRequest};
use anyhow::Result;
use async_trait::async_trait;
use super::async_read_write::AsyncReadWrite;

pub type AsyncReadWriteStream = Pin<Box<dyn AsyncReadWrite>>;

#[async_trait]
pub(crate) trait OutBoundProxy: Send + Sync {
    async fn connect_server(&self, connect_request: ConnectRequest) -> Result<AsyncReadWriteStream>;
}
