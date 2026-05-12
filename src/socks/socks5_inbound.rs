use std::sync::Arc;

use anyhow::Result;

use crate::{ProxyError, dns_config::DnsConfig};
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
            if let Ok((stream, addr)) = listener.accept().await {
                log::info!("received stream from addr:{}", &addr);

                let config = self.config.clone();
                let dns_config = self.dns_config.clone();

                tokio::spawn(async move {
                    let mut handler = Socks5InBoundHanlder::new(stream, config, dns_config);
                    if let Err(err) = handler.handlestream().await {
                        log::error!("Socks5 handle stream failed, inner error: {}", err);
                    }
                });
            }
        }
    }
}

#[allow(unused)]
struct Socks5InBoundHanlder {
    stream: TcpStream,
    inbound_config: Arc<SocksInBoundConfig>,
    dns_config: Arc<DnsConfig>,
}

impl Socks5InBoundHanlder {
    fn new(stream: TcpStream, in_conf: Arc<SocksInBoundConfig>, dns_conf: Arc<DnsConfig>) -> Self {
        Self {
            stream,
            inbound_config: in_conf,
            dns_config: dns_conf,
        }
    }
    async fn handlestream(&mut self) -> Result<()> {
        self.auth_handle().await?;
        self.bind_remote().await?;
        Ok(())
    }

    #[allow(unused)]
    fn auth_uid(&self) -> Option<&str> {
        self.inbound_config.uid()
    }
    #[allow(unused)]
    fn auth_pwd(&self) -> Option<&str> {
        self.inbound_config.pwd()
    }

    async fn auth_handle(&mut self) -> Result<()> {
        log::trace!("start auth");
        valid_socks_ver(&mut self.stream).await?;
        let method_lens = self.stream.read_u8().await? as usize;
        let mut buff = vec![0u8; method_lens];
        let n = self.stream.read_exact(&mut buff).await?;
        if !n.eq(&method_lens) {
            return Err(ProxyError::Socks5AuthError(format!(
                "received lens:{n} not eq defined lens:{method_lens}"
            ))
            .into());
        }
        let auth_methods_from_client: Vec<_> = buff.iter().map(AuthMethod::from).collect();
        log::trace!(
            "client support auth methods:{:?}",
            &auth_methods_from_client
        );
        let support_auth = get_both_auth_method(&auth_methods_from_client)
            .ok_or(ProxyError::Socks5NoSupportAuthMethod)?;
        log::trace!("final authmethod:{:?}", support_auth);

        self.stream
            .write_all(&[SOCKS_VERSION, (*support_auth).into()])
            .await?;

        //todo:实现其他认证
        if support_auth.eq(&AuthMethod::NoAuth) {
            Ok(())
        } else {
            unimplemented!("socks5支持其他认证方法")
        }
    }

    async fn bind_remote(&mut self) -> Result<()> {
        valid_socks_ver(&mut self.stream).await?;

        let mut response_builder = SocksResponse::builder();

        let cmd_byte = self.stream.read_u8().await?;
        let cmd = Cmd::try_from(cmd_byte)?;
        log::trace!("the client cmd is: {:?}", cmd);
        //读取rsv，该位没用
        let _rsv = self.stream.read_u8().await?;
        let connect_request = read_address(&mut self.stream).await?;
        log::trace!("read address success, {}", connect_request);

        response_builder
            .atyp(connect_request.dst_as_atp())
            .dst_addr(connect_request.addr())
            .dst_port(connect_request.port());

        match cmd {
            Cmd::Connect => {
                let outbound_config = APP_CONFIG.get_forward_to_remote(&connect_request).await?;

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
        return Err(ProxyError::Socks5VersionIncorrect.into());
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

fn get_both_auth_method(client_auth_methods: &[AuthMethod]) -> Option<&AuthMethod> {
    let mut v: Vec<_> = client_auth_methods
        .iter()
        .filter(|&am| SERVER_SUPPORTED_AUTHS.contains(am))
        .collect();
    v.sort_by(|&x, &y| y.cmp(x));
    match v.first() {
        Some(&am) => Some(am),
        None => None,
    }
}
/*ATYP (1 字节): DST.ADDR 字段的地址类型。
X'01' (1): IPv4 地址，DST.ADDR 字段⻓度为 4 字节。
X'03' (3): 域名，DST.ADDR 字段的第⼀个字节表示域名⻓度，后续是域名本身。
X'04' (4): IPv6 地址，DST.ADDR 字段⻓度为 16 字节。
DST.ADDR (可变⻓度): ⽬标地址。⻓度由 ATYP 字段决定。
DST.PORT (2 字节): ⽬标端⼝号（⽹络字节序，即⼤端序）。
*/
async fn read_address(stream: &mut TcpStream) -> Result<ConnectRequest> {
    let t = stream.read_u8().await?;
    match t {
        0x01 => {
            let mut buf = [0; 4];
            stream.read_exact(&mut buf).await?;
            let port = stream.read_u16().await?;
            ConnectRequest::try_from((SocksAddressType::Ipv4, &buf[..], port))
        }
        0x03 => {
            let len = stream.read_u8().await.expect("get domain length") as usize;
            let mut domain = vec![0; len];
            stream.read_exact(&mut domain).await?;
            let port = stream.read_u16().await?;
            ConnectRequest::try_from((SocksAddressType::Domain, &domain[..], port))
        }
        0x04 => {
            let mut buf = [0; 16];
            stream.read_exact(&mut buf).await?;
            let port = stream.read_u16().await?;
            ConnectRequest::try_from((SocksAddressType::Ipv6, &buf[..], port))
        }
        _ => Err(ProxyError::Socks5UnknownAtyp.into()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn get_both_auth_method_test() {
        let client_auth_methods = [AuthMethod::NoAuth, AuthMethod::UserPwd];
        let supported = get_both_auth_method(&client_auth_methods);
        assert_eq!(supported, Some(&AuthMethod::UserPwd));
    }
}
