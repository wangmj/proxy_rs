use std::{net::SocketAddr, sync::Arc};

use anyhow::{Result, anyhow};
use async_trait::async_trait;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
};

use crate::{
    app_config::{APP_CONFIG, EthanInBoundConfig},
    ethan_proto::{AuthRequest, ConnectRequest, EthanResponse},
    factory::outbound_factory::{OutBoundFactory},
    traits::proxy_inbound::InBoundProxy,
};

pub struct EthanInBound {
    config: Arc<EthanInBoundConfig>,
}

impl EthanInBound {
    pub fn new(config: Arc<EthanInBoundConfig>) -> Self {
        Self { config }
    }
}

#[async_trait]
impl InBoundProxy for EthanInBound {
    async fn start(&self) {
        let port = self.config.port();
        let listener = TcpListener::bind(("0.0.0.0", port))
            .await
            .expect("failed to start listen");
        log::trace!("ethan server start listening at port: {}", port);
        while let Ok((stream, addr)) = listener.accept().await {
            //todo: 此处没有将正在处理的线程保存，所以在停止时可能会导致正在处理的数据丢失。
            handlstream(stream, addr).await;
        }
    }
}
async fn handlstream(mut stream: TcpStream, addr: SocketAddr) {
    log::trace!("ethan server rev connect, remote :{:?}", addr);
    tokio::spawn(async move {
        if auth_handle(&mut stream).await.is_err() {
            log::error!("ethan server rev auth request, but failed!");
            return;
        }
        let mut out_stream = bind_handle(&mut stream)
            .await
            .expect("bind to server failed");
        match tokio::io::copy_bidirectional(&mut stream, &mut out_stream).await {
            Ok((n, m)) => {
                println!("copied {}:{} bites", n, m)
            }
            Err(err) => {
                eprintln!("data transfer broken out with error: {}", err);
            }
        }
    });
}

async fn auth_handle(stream: &mut TcpStream) -> Result<()> {
    let lens = stream.read_u8().await? as usize;
    log::trace!("ethan server received client auth request,lens: {}", lens);
    let mut buff = vec![0u8; lens];
    stream.read_exact(&mut buff).await?;
    println!("{:?}", buff);
    let request = AuthRequest::try_from(buff.as_slice())?;
    log::trace!("ethan server received client auth request: {:?}", request);
    if request.uid().eq("uid") && request.pwd().eq("pwd") {
        let response = EthanResponse::new(true, None);
        let response = response.as_bytes();
        stream.write_u8(response.len() as u8).await?;
        stream.write_all(response.as_slice()).await?;
        log::trace!("ethan server client auth uid and pwd is correct!");
        Ok(())
    } else {
        log::error!("ethan server client auth uid and pwd is incorrect!");
        let response = EthanResponse::new(true, Some("uid and pwd is incorrect".into()));
        let response = response.as_bytes();
        stream.write_u8(response.len() as u8).await?;
        stream.write_all(response.as_slice()).await?;
        Err(anyhow!("uid and pwd is incorrect"))
    }
}

async fn bind_handle(in_stream: &mut TcpStream) -> Result<TcpStream> {
    let lens = in_stream.read_u8().await? as usize;
    let mut buff = vec![0u8; lens];
    in_stream.read_exact(&mut buff).await?;
    let request = ConnectRequest::try_from(buff.as_slice())?;

    let output_bound = OutBoundFactory::get(APP_CONFIG.outbound());
    match output_bound.connect_server(request).await {
        Ok(out_stream) => {
            let response = EthanResponse::new(true, None);
            let bytes = response.as_bytes();
            in_stream.write_u8(bytes.len() as u8).await?;
            in_stream.write_all(&bytes).await?;
            Ok(out_stream)
        }
        Err(err) => {
            let response = EthanResponse::new(false, Some(err.to_string()));
            let bytes = response.as_bytes();
            in_stream.write_u8(bytes.len() as u8).await?;
            in_stream.write_all(&bytes).await?;
            Err(err)
        }
    }
}
