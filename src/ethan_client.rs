use std::net::SocketAddr;

use anyhow::{Result, anyhow};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
    sync::mpsc::{Receiver, Sender},
};

use crate::ethan_proto::{AuthRequest, ConnectRequest, DstType, EthanResponse};

pub struct EthanClient {
    server_addr: SocketAddr,
}

impl EthanClient {
    pub async fn connect_server(&self) -> Result<TcpStream> {
        let stream = TcpStream::connect(self.server_addr).await?;
        Ok(stream)
    }

    pub async fn new(
        addr: SocketAddr,
        notify_rv: Receiver<String>,
        socket_tx: Sender<TcpStream>,
    ) -> Self {
        let s = Self { server_addr: addr };
        s.rev_notify_send_socket(notify_rv, socket_tx).await;
        s
    }

    async fn rev_notify_send_socket(&self, mut rv: Receiver<String>, tx: Sender<TcpStream>) {
        while let Some(msg) = rv.recv().await {
            if !msg.is_empty() {
                let socket = self.connect_server().await.expect("get socket failed!");
                match tx.send(socket).await {
                    Ok(_) => {}
                    Err(err) => log::error!("send socket to mpsc failed! {}", err),
                }
            }
        }
    }
}
pub async fn auth(stream: &mut TcpStream) -> Result<()> {
    let auth_request = AuthRequest::new("uid".to_string(), "pwd".to_string());
    let mut auth_bytes = auth_request.as_bytes();
    auth_bytes.insert(0, auth_bytes.len() as u8);
    stream.write_all(&auth_bytes).await?;

    let len = stream.read_u8().await? as usize;
    let mut buff = vec![0u8; len];
    stream.read_exact(&mut buff).await?;
    let response = EthanResponse::try_from(&buff[..])?;
    if response.res() {
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

pub(crate) async fn bind_request(stream: &mut TcpStream, port: u16, dst: DstType) -> Result<()> {
    let ccmd = ConnectRequest::new(port, dst);
    let ccmd_bytes = ccmd.as_bytes();
    stream.write_u8(ccmd_bytes.len() as u8).await?;
    stream.write_all(&ccmd_bytes).await?;

    let len = stream.read_u8().await?;
    let mut buff = vec![0u8; len as usize];
    stream.read_buf(&mut buff).await?;
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
