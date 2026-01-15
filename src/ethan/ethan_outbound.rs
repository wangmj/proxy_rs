use std::sync::Arc;

use anyhow::{Result, anyhow};
use async_trait::async_trait;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
};

use crate::{
    app_config::EthanOutBoundConfig,
    ethan::ethan_proto::{AuthRequest, ConnectRequest, DstType, EthanResponse},
    traits::proxy_outbound::OutBoundProxy,
};

pub struct EthanOutBound {
    config: Arc<EthanOutBoundConfig>,
}

impl EthanOutBound {
    pub(crate) fn new(config: Arc<EthanOutBoundConfig>) -> Self {
        Self { config }
    }
}

#[async_trait]
impl OutBoundProxy for EthanOutBound {
    async fn connect_server(
        &self,
        connect_request: ConnectRequest,
    ) -> Result<tokio::net::TcpStream> {
        let addr = self.config.socket_addr().await?;
        let mut stream = TcpStream::connect(addr).await?;
        auth_request(&mut stream, self.config.clone()).await?;
        bind_request(
            &mut stream,
            connect_request.port(),
            connect_request.dst_type(),
        )
        .await?;
        Ok(stream)
    }
}
pub async fn auth_request(stream: &mut TcpStream, config: Arc<EthanOutBoundConfig>) -> Result<()> {
    log::trace!("ethan client start auth with server");

    let auth_request = AuthRequest::new(config.uid().to_string(), config.pwd().to_string());
    let auth_bytes = auth_request.as_bytes();
    stream.write_u8(auth_bytes.len() as u8).await?;
    stream.write_all(&auth_bytes).await?;
    log::trace!("ethan client send auth to server");

    let len = stream.read_u8().await? as usize;
    let mut buff = vec![0u8; len];
    stream.read_exact(&mut buff).await?;
    log::trace!("ethan client received server auth response");
    let response = EthanResponse::try_from(&buff[..])?;
    if response.res() {
        log::trace!("ethan client received server auth response: success");
        Ok(())
    } else {
        Err(anyhow!(
            "auth failed. err: {}",
            response
                .reason()
                .as_deref()
                .unwrap_or("server not return auth failed reason")
        ))
    }
}

pub(crate) async fn bind_request(stream: &mut TcpStream, port: u16, dst: &DstType) -> Result<()> {
    let ccmd = ConnectRequest::new(port, dst.clone());
    let ccmd_bytes = ccmd.as_bytes();
    stream.write_u8(ccmd_bytes.len() as u8).await?;
    stream.write_all(&ccmd_bytes).await?;

    let len = stream.read_u8().await?;
    let mut buff = vec![0u8; len as usize];
    stream.read_exact(&mut buff).await?;
    let response = EthanResponse::try_from(&buff[..])?;
    if response.res() {
        Ok(())
    } else {
        Err(anyhow!(
            "bind failed, err: {}",
            response
                .reason()
                .as_deref()
                .unwrap_or("server not return auth failed reason")
        ))
    }
}
