use std::sync::Arc;

use anyhow::{Result, anyhow};

use crate::{
    dns_config::{DNSResolver, DnsConfig},
    dns_resolver,
    ethan::ethan_proto::DstType,
};
use async_trait::async_trait;
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::{TcpListener, TcpStream},
};

use crate::{
    APP_CONFIG, SocksInBoundConfig,
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
    dns_config: Arc<DnsConfig>,
}

impl Socks5InBound {
    pub fn new(config: Arc<SocksInBoundConfig>, dns_config: Arc<DnsConfig>) -> Self {
        Self { config, dns_config }
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
            let dns_config=self.dns_config.clone();
            if let Ok((stream, addr)) = listener.accept().await {
                log::info!("received stream from addr:{}", &addr);
                tokio::spawn(async move {
                    let mut handler =
                        Socks5InBoundHanlder::new(stream, config, dns_config);
                    if let Err(err) = handler.handlestream().await {
                        log::error!("handle stream failed, inner error: {}", err);
                    }
                });
            }
        }
    }
}

struct Socks5InBoundHanlder {
    stream: TcpStream,
    inbound_config: Arc<SocksInBoundConfig>,
    dns_config: Arc<DnsConfig>,
}

impl Socks5InBoundHanlder {
    fn new(
        stream: TcpStream,
        in_conf: impl Into<Arc<SocksInBoundConfig>>,
        dns_conf: Arc<DnsConfig>,
    ) -> Self {
        Self {
            stream,
            inbound_config: in_conf.into(),
            dns_config: dns_conf,
        }
    }
    fn auth_uid(&self) -> Option<&str> {
        self.inbound_config.uid()
    }
    fn auth_pwd(&self) -> Option<&str> {
        self.inbound_config.pwd()
    }
    async fn handlestream(&mut self) -> Result<()> {
        if let Err(err) = self.auth_handle().await {
            return Err(anyhow!(
                "there is some error when process auth, inner error: {err}"
            ));
        }

        self.bind_remote().await?;
        Ok(())
    }

    async fn auth_handle(&mut self) -> Result<()> {
        log::trace!("start auth");
        valid_socks_ver(&mut self.stream).await?;
        let method_lens = self.stream.read_u8().await? as usize;
        let mut buff = vec![0u8; method_lens];
        let n = self.stream.read_exact(&mut buff).await?;
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
        self.stream
            .write_all(&[SOCKS_VERSION, support_auth.into()])
            .await?;

        if support_auth.eq(&AuthMethod::NoAuth) {
            Ok(())
        } else {
            todo!("socks5支持其他认证方法")
        }
    }

    async fn bind_remote(&mut self) -> Result<()> {
        valid_socks_ver(&mut self.stream).await?;

        let mut response_builder = SocksResponse::builder();

        let cmd_byte = self.stream.read_u8().await?;
        let cmd = match Cmd::try_from(cmd_byte) {
            Ok(cmd) => cmd,
            Err(e) => return Err(e),
        };
        log::trace!("the client cmd is: {:?}", cmd);
        //读取rsv，该位没用
        let _rsv = self.stream.read_u8().await?;
        let mut connect_request = read_address(&mut self.stream).await?;
        log::trace!("read address success, {}", connect_request);

        response_builder
            .atyp(connect_request.dst_as_atp())
            .dst_addr(connect_request.addr())
            .dst_port(connect_request.port());

        match cmd {
            Cmd::Connect => {
                if SocksAddressType::Domain == connect_request.dst_as_atp()
                    && let DNSResolver::Local = self.dns_config.resolver
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
                        self.stream.write_all(&response).await?;
                        self.stream.flush().await?;
                        transfer_data(&mut self.stream, &mut outbound_stream).await;
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
