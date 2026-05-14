use std::{
    sync::{Arc, atomic::AtomicUsize},
    time::Duration,
};

use anyhow::Result;

use crate::{ProxyError, dns_config::DnsConfig, shutdown_listener};
use async_trait::async_trait;
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    sync::broadcast::Receiver,
    task::JoinSet,
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

static ACTIVE_CONNECTIONS: AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
///socks代理入口
pub struct Socks5InBound {
    config: Arc<SocksInBoundConfig>,
    dns_config: Arc<DnsConfig>,
    shutdown_rev: Receiver<()>,
}

impl Socks5InBound {
    pub fn new(config: Arc<SocksInBoundConfig>, dns_config: Arc<DnsConfig>) -> Self {
        let shutdown_rev = shutdown_listener();
        Self { config, dns_config, shutdown_rev }
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
            listener.local_addr().expect("failed get local addr on socks5")
        );
        print_active_connections();
        let mut shutdown_listener = self.shutdown_rev.resubscribe();
        let mut joinsets = JoinSet::new();
        loop {
            tokio::select! {
                res=listener.accept() =>{
                    if let Ok((stream, addr))=res{
                         log::debug!("received stream from addr:{}", &addr);

                        let config = self.config.clone();
                        let dns_config = self.dns_config.clone();
                        let mut shutdown=self.shutdown_rev.resubscribe();

                        joinsets.spawn(async move {
                            ACTIVE_CONNECTIONS.fetch_add(1, std::sync::atomic::Ordering::Relaxed);

                            let mut handler = Socks5InBoundHanlder::new(stream, config, dns_config);
                            tokio::select!{
                                 _=shutdown.recv()=>{
                                    log::info!("had recv close signal, can't process new connection");
                                },
                                res=handler.handlestream()=>{
                                    if let Err(err)=res{
                                        log::error!("Socks5 handle stream failed, inner error: {}", err);
                                    }
                                }
                            }

                            ACTIVE_CONNECTIONS.fetch_sub(1, std::sync::atomic::Ordering::Relaxed);
                        });
                    }
            },
                _=shutdown_listener.recv()=>{
                    log::info!("stop listener...");
                    break;
                }
            }
        }

        match tokio::time::timeout(Duration::from_secs(5), joinsets.join_all()).await {
            Ok(_) => {
                log::info!("all connection had closed");
            }
            Err(_) => {
                log::error!("wait for connection timeout, will shutdown force..");
            }
        }
    }
}

fn print_active_connections() {
    let mut interval = tokio::time::interval(Duration::from_secs(5));
    tokio::spawn(async move {
        loop {
            let _ = interval.tick().await;
            let count = ACTIVE_CONNECTIONS.load(std::sync::atomic::Ordering::Relaxed);
            log::info!("Active connection: {}", count);
        }
    });
}
#[allow(unused)]
struct Socks5InBoundHanlder {
    stream: TcpStream,
    inbound_config: Arc<SocksInBoundConfig>,
    dns_config: Arc<DnsConfig>,
}

impl Socks5InBoundHanlder {
    fn new(stream: TcpStream, in_conf: Arc<SocksInBoundConfig>, dns_conf: Arc<DnsConfig>) -> Self {
        Self { stream, inbound_config: in_conf, dns_config: dns_conf }
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
        log::trace!("client support auth methods:{:?}", &auth_methods_from_client);
        let support_auth = get_both_auth_method(&auth_methods_from_client)
            .ok_or(ProxyError::Socks5NoSupportAuthMethod)?;
        log::trace!("final authmethod:{:?}", support_auth);

        self.stream.write_all(&[SOCKS_VERSION, (*support_auth).into()]).await?;

        match support_auth {
            AuthMethod::NoAuth => Ok(()),
            AuthMethod::UserPwd => {
                user_pwd_auth(&mut self.stream, self.inbound_config.clone()).await
            }
            AuthMethod::Gssapi => Err(ProxyError::Socks5NoSupportAuthMethod.into()),
            AuthMethod::Reject => Err(ProxyError::Socks5AuthReject.into()),
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

                match OutBoundFactory::get(&outbound_config).connect_server(connect_request).await {
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

//socks5 user pwd认证
async fn user_pwd_auth(
    handler: &mut TcpStream, inbound_config: Arc<SocksInBoundConfig>,
) -> Result<()> {
    let send_result = async |handler: &mut TcpStream, res: bool| {
        match res {
            //X'00' (0): 认证成功。
            //X'01' (1): 认证失败。
            true => handler.write_all(&[1u8, 0]).await,
            false => handler.write_all(&[1u8, 1]).await,
        }
    };
    let ver = handler.read_u8().await?;
    if !ver.eq(&1) {
        send_result(handler, false).await?;
        return Err(ProxyError::Socks5VersionIncorrect.into());
    }

    let u_lens = handler.read_u8().await?;
    log::trace!("socks5 user_lens:{u_lens}");
    let mut user_buff = vec![0u8; u_lens as usize];
    let u_lens_read = handler.read_exact(&mut user_buff).await?;
    if !u_lens.eq(&(u_lens_read as u8)) {
        send_result(handler, false).await?;
        return Err(ProxyError::LengthNotMatchedAggree("Socks5 Auth user name".into()).into());
    }
    let user_read = String::from_utf8_lossy(&user_buff);
    log::trace!("user name from client:{user_read}");
    if !user_read.eq(&inbound_config.uid().unwrap_or_default()) {
        send_result(handler, false).await?;
        return Err(ProxyError::Socks5AuthError("User is incorrect!".into()).into());
    }

    let p_lens = handler.read_u8().await? as usize;
    log::trace!("socks5 pwd_lens:{p_lens}");
    let mut p_buff = vec![0u8; p_lens];
    let p_lens_read = handler.read_exact(&mut p_buff).await?;
    if !p_lens_read.eq(&p_lens) {
        send_result(handler, false).await?;
        return Err(ProxyError::LengthNotMatchedAggree("Socks5 Auth pwd".into()).into());
    }
    let pwd_read = String::from_utf8_lossy(&p_buff);
    log::debug!("pwd from client:{pwd_read}");
    if !pwd_read.eq(&inbound_config.pwd().unwrap_or_default()) {
        send_result(handler, false).await?;
        return Err(ProxyError::Socks5AuthError("Pwd is incorrect!".into()).into());
    }

    send_result(handler, true).await?;
    log::debug!("socks5 auth success!");

    Ok(())
}

async fn transfer_data<A, B>(in_stream: &mut A, out_stream: &mut B)
where
    A: AsyncRead + AsyncWrite + Unpin + ?Sized,
    B: AsyncRead + AsyncWrite + Unpin + ?Sized,
{
    log::debug!("starting transfer data");
    match tokio::io::copy_bidirectional(in_stream, out_stream).await {
        Ok(n) => {
            log::trace!("copied {}:{} bites", n.0, n.1);
        }
        Err(err) => {
            let err_str = err.to_string();
            if err_str.contains("close_notify") || err_str.contains("unexpected-eof") {
                log::debug!("{err_str}");
            } else {
                log::warn!("copied occured error, {}", err)
            }
        }
    }
}

fn get_both_auth_method(client_auth_methods: &[AuthMethod]) -> Option<&AuthMethod> {
    let mut v: Vec<_> =
        client_auth_methods.iter().filter(|&am| SERVER_SUPPORTED_AUTHS.contains(am)).collect();
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
