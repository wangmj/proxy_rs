use std::{sync::Arc, time::Duration};

use anyhow::{Result, anyhow};

use crate::{dns_resolver, ethan::ethan_proto::DstType};
use async_trait::async_trait;
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    sync::RwLock,
    task::JoinHandle,
};

use crate::{
    APP_CONFIG, DNSResolver, SocksInBoundConfig,
    ethan::ethan_proto::ConnectRequest,
    factory::outbound_factory::*,
    socks::socks5_proto::{
        AuthMethod, Cmd, SERVER_SUPPORTED_AUTHS, SOCKS_VERSION, SocksAddressType, SocksResponse,
        SocksResponseType,
    },
    traits::proxy_inbound::InBoundProxy,
};

///socks代理入口
pub struct Socks5InBound {
    config: Arc<SocksInBoundConfig>,
}

impl Socks5InBound {
    pub fn new(config: Arc<SocksInBoundConfig>) -> Self {
        Self { config }
    }
}

#[async_trait]
impl InBoundProxy for Socks5InBound {
    async fn start(&self) {
        let listener_port = self.config.port();
        let listener = TcpListener::bind(format!("0.0.0.0:{}", listener_port))
            .await
            .expect("failed to start listen");
        log::info!(
            "socks5 start listening on port:{}",
            listener
                .local_addr()
                .expect("failed get local addr on socks5")
        );
        loop {
            let config = self.config.clone();
            if let Ok((stream, addr)) = listener.accept().await {
                log::info!("received stream from addr:{}", &addr);
                tokio::spawn(async move {
                    if let Err(err) = handlestream(stream, config).await {
                        log::error!("handle stream failed, inner error: {}", err);
                    }
                });
            }
        }
    }
}

async fn handlestream(mut stream: TcpStream, config: Arc<SocksInBoundConfig>) -> Result<()> {
    let uid = Arc::new(config.uid().map(|x| x.to_string()));
    let pwd = Arc::new(config.pwd().map(|x| x.to_string()));

    if let Err(err) = auth_handle(&mut stream, uid, pwd).await {
        return Err(anyhow!(
            "there is some error when process auth, inner error: {err}"
        ));
    }

    bind_remote(&mut stream, config).await?;
    Ok(())
}

async fn valid_socks_ver(stream: &mut TcpStream) -> Result<()> {
    let ver = stream.read_u8().await?;
    if !ver.eq(&SOCKS_VERSION) {
        let msg = "socks version is incorrect";
        log::warn!("{}", msg);
        return Err(anyhow!(msg));
    }
    log::trace!("the socks version is correct!");
    Ok(())
}
async fn auth_handle(
    stream: &mut TcpStream,
    _uid: Arc<Option<String>>,
    _pwd: Arc<Option<String>>,
) -> Result<()> {
    log::trace!("start auth");
    valid_socks_ver(stream).await?;
    let method_lens = stream.read_u8().await? as usize;
    let mut buff = vec![0u8; method_lens];
    let n = stream.read_exact(&mut buff).await?;
    if !n.eq(&method_lens) {
        return Err(anyhow!(format!(
            "received client support method failed! received lens:{} not eq defined lens:{}",
            n, method_lens
        )));
    }
    let auth_methods_from_client: Vec<_> = buff.iter().map(AuthMethod::from).collect();
    log::trace!(
        "client support auth methods:{:?}",
        &auth_methods_from_client
    );
    let mut both_supported_authmethods =
        find_both_support_auth_method(&auth_methods_from_client, &SERVER_SUPPORTED_AUTHS);
    both_supported_authmethods.sort();
    let support_auth = match both_supported_authmethods.first() {
        Some(am) => *am,
        None => {
            let msg = format!(
                "There is no method with server and client all support,client supported methods:{:?}, server support methods:{:?}",
                auth_methods_from_client, SERVER_SUPPORTED_AUTHS
            );
            return Err(anyhow!(msg));
        }
    };
    log::trace!("final authmethod:{:?}", &support_auth);
    stream
        .write_all(&[SOCKS_VERSION, support_auth.into()])
        .await?;

    if support_auth.eq(&AuthMethod::NoAuth) {
        Ok(())
    } else {
        todo!("socks5支持其他认证方法")
    }
}

async fn bind_remote(stream: &mut TcpStream, config: Arc<SocksInBoundConfig>) -> Result<()> {
    valid_socks_ver(stream).await?;

    let mut response_builder = SocksResponse::builder();

    let cmd_byte = stream.read_u8().await?;
    let cmd = match Cmd::try_from(cmd_byte) {
        Ok(cmd) => cmd,
        Err(e) => return Err(e),
    };
    log::trace!("the client cmd is: {:?}", cmd);
    //读取rsv，该位没用
    let _rsv = stream.read_u8().await?;
    let mut connect_request = read_address(stream).await?;
    log::trace!("read address success, {}", connect_request);

    response_builder
        .atyp(connect_request.dst_as_atp())
        .dst_addr(connect_request.addr())
        .dst_port(connect_request.port());

    match cmd {
        Cmd::Connect => {
            if SocksAddressType::Domain == connect_request.dst_as_atp()
                && let DNSResolver::Local = config.dns().resolver
            {
                let addr = connect_request.addr();
                let ds = String::from_utf8_lossy(&addr);
                let ips = dns_resolver::resolve_dns(&ds).await?;
                let ip = dns_resolver::pick_fastet_ipadd(&ips, connect_request.port())
                    .await
                    .ok_or_else(|| anyhow!(format!("can't resolve dns:{} to ip", ds)))?;
                match ip {
                    std::net::IpAddr::V4(ipv4_addr) => {
                        connect_request.set_dst_type(DstType::Ipv4(ipv4_addr));
                    }
                    std::net::IpAddr::V6(ipv6_addr) => {
                        connect_request.set_dst_type(DstType::Ipv6(ipv6_addr))
                    }
                }
            }
            let outbound_config = APP_CONFIG.get_forward_to_remote(&connect_request)?;

            match OutBoundFactory::get(&outbound_config)
                .connect_server(connect_request)
                .await
            {
                Ok(mut outbound_stream) => {
                    response_builder.rep(SocksResponseType::Success);
                    let response = response_builder.build();
                    let response = response.to_bytes();
                    stream.write_all(&response).await?;
                    stream.flush().await?;
                    transfer_data(stream, &mut outbound_stream).await;
                }
                Err(err) => {
                    log::error!("Outbound connect remote server failed. {}", err);
                    response_builder.rep(SocksResponseType::ConnectReject);
                }
            }
        }
        Cmd::Bind => todo!(),
        Cmd::Udp => todo!(),
    }

    Ok(())
}

async fn transfer_data<A, B>(in_stream: &mut A, out_stream: &mut B)
where
    A: AsyncRead + AsyncWrite + Unpin + ?Sized,
    B: AsyncRead + AsyncWrite + Unpin + ?Sized,
{
    log::trace!("starting transfer data");
    match tokio::io::copy_bidirectional(in_stream, out_stream).await {
        Ok(n) => {
            log::trace!("copied {}:{} bites", n.0, n.1);
        }
        Err(err) => log::warn!("copied occured error, {}", err),
    }
}

//todo: 优化该代码，返回借用的值
fn find_both_support_auth_method(
    client_auth_methods: &[AuthMethod],
    server_auth_methods: &[AuthMethod],
) -> Vec<AuthMethod> {
    server_auth_methods
        .iter()
        .filter(|sm| client_auth_methods.contains(sm))
        .copied()
        .collect()
}

async fn read_address(stream: &mut TcpStream) -> Result<ConnectRequest> {
    let t = stream.read_u8().await?;
    match t {
        0x01 => {
            let mut buf = [0; 4];
            stream.read_exact(&mut buf).await?;
            let port = stream.read_u16().await?;
            ConnectRequest::try_from((SocksAddressType::Ipv4, &buf[..], port))
            // Ok((SocksAddressType::Ipv4, buf.to_vec(), port))
        }
        0x03 => {
            let len = stream.read_u8().await.expect("get domain length") as usize;
            let mut domain = vec![0; len];
            stream.read_exact(&mut domain).await?;
            let port = stream.read_u16().await?;
            ConnectRequest::try_from((SocksAddressType::Domain, &domain[..], port))
            // Ok((SocksAddressType::Domain, domain, port))
        }
        0x04 => {
            let mut buf = [0; 16];
            stream.read_exact(&mut buf).await?;
            let port = stream.read_u16().await?;
            ConnectRequest::try_from((SocksAddressType::Ipv6, &buf[..], port))
            // Ok((SocksAddressType::Ipv6, buf.to_vec(), port))
        }
        _ => Err(anyhow!(format!("unkonw atyp: {}", t))),
    }
}
