use std::net::{SocketAddr, SocketAddrV4, SocketAddrV6};

use anyhow::{Result, anyhow};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
};

use crate::{
    dns_resolver::{pick_fastet_ipadd, resolve_dns},
    ethan_proto::{AuthRequest, ConnectRequest, EthanResponse},
};

pub struct EthanServer {
    listen_port: u16,
}

impl EthanServer {
    pub fn new(port: u16) -> Self {
        Self { listen_port: port }
    }
    pub async fn start(&self) {
        let listener = TcpListener::bind(("0.0.0.0", self.listen_port))
            .await
            .expect("failed to start listen");
        log::trace!("ethan server start listening at port: {}", self.listen_port);
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
    // log::trace!("ethan server received client auth request,lens: {}",lens);
    
    let lens = stream.read_u8().await? as usize;
    let mut buff = vec![0u8; lens];
    stream.read_exact(&mut buff).await?;
    println!("{:?}",buff);
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

    //todo:将此处换成工厂
    match connect_server(&request).await {
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

async fn connect_server(request: &ConnectRequest) -> Result<TcpStream> {
    let port = request.port();
    let stream = match request.dst_type() {
        crate::ethan_proto::DstType::Ipv4(ipv4_addr) => {
            TcpStream::connect(SocketAddrV4::new(*ipv4_addr, port)).await?
        }
        crate::ethan_proto::DstType::Ipv6(ipv6_addr) => {
            TcpStream::connect(SocketAddrV6::new(*ipv6_addr, port, 0, 0)).await?
        }
        crate::ethan_proto::DstType::DomainName(domain_name) => {
            let addrs = resolve_dns(&domain_name).await?;
            let ipaddr = match pick_fastet_ipadd(&addrs, port).await {
                Some(ip) => ip,
                None => {
                    return Err(anyhow!(format!(
                        "can't resovle domainName:{} with correct ip",
                        domain_name
                    )));
                }
            };
            TcpStream::connect(SocketAddr::new(ipaddr, port)).await?
        }
    };
    Ok(stream)
}
