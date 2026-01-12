use std::{
    sync::Arc,
    time::Duration,
};

use anyhow::{Result, anyhow};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    sync::RwLock,
    task::JoinHandle,
};

use crate::{
    ethan_proto::ConnectRequest,
    proxy_outbound::{OutBoundFactory, OutBoundType},
    socks5_proto::{
        AuthMethod, Cmd, SERVER_SUPPORTED_AUTHS, SOCKS_VERSION, SocksAddressType, SocksResponse,
    },
};
pub struct Socks5Services {
    handlers: Arc<RwLock<Vec<JoinHandle<()>>>>,
    clean_interval_sec: usize,
}

impl Socks5Services {
    pub async fn start(&self) -> Result<()> {
        let listener_port = 1080;
        let listener = TcpListener::bind(format!("0.0.0.0:{}", listener_port)).await?;
        log::info!(
            "socks5 start listening on port:{}",
            listener
                .local_addr()
                .expect("failed get local addr on socks5")
        );
        loop {
            if let Ok((stream, addr)) = listener.accept().await {
                log::info!("received stream from addr:{}", &addr);
                let t = tokio::spawn(async move {
                    match handlestream(stream).await {
                        Ok(_) => {}
                        Err(err) => {
                            log::error!("there is an error when handle stream, {}", err);
                        }
                    }
                });
                self.handlers.write().await.push(t);
            }
        }

        // Ok(())
    }
     async fn clean(&self) {
        let handlers = self.handlers.clone();
        let sleep_sec = self.clean_interval_sec as u64;
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(Duration::from_secs(sleep_sec)).await;
                //先将已经完成的收集起来
                let had_finished: Vec<_> = handlers
                    .read()
                    .await
                    .iter()
                    .enumerate()
                    .filter(|(_i, t)| t.is_finished())
                    .map(|(i, _)| i)
                    .collect();

                //如果已经完成的不为空，则循环删除。先判断一下，以防止不必要获取读指针。
                if !had_finished.is_empty() {
                    let mut write_handler = handlers.write().await;
                    had_finished.iter().rev().for_each(|i| {
                        write_handler.remove(*i);
                    });
                }
            }
        });
    }
    pub async  fn new() -> Self {
        let s = Self {
            handlers: Arc::new(RwLock::new(Vec::new())),
            clean_interval_sec: 10,
        };
        s.clean().await;
        s
    }
}

async fn handlestream(mut stream: TcpStream) -> Result<()> {
    auth_handle(&mut stream).await?;

    bind_remote(&mut stream).await?;
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
async fn auth_handle(stream: &mut TcpStream) -> Result<()> {
    valid_socks_ver(stream).await?;
    log::trace!("start auth");
    let method_lens = stream.read_u8().await? as usize;
    let mut buff = vec![0u8; method_lens];
    let _n = stream.read_exact(&mut buff).await?;
    if !_n.eq(&method_lens) {
        let msg = format!(
            "received client support method failed! received lens:{} not eq defined lens:{}",
            _n, method_lens
        );
        log::error!("{}", msg);
        return Err(anyhow!(msg));
    }
    let auth_methods_from_client: Vec<_> = buff.iter().map( AuthMethod::from).collect();
    log::trace!(
        "client support auth methods:{:?}",
        &auth_methods_from_client
    );
    let mut both_supported_authmethods =
        find_both_support_auth_method(&auth_methods_from_client, &SERVER_SUPPORTED_AUTHS);
    both_supported_authmethods.sort();
    let first_supported_am = both_supported_authmethods.first();
    let am = match first_supported_am {
        Some(am) => *am,
        None => {
            let msg = format!(
                "There is no method with server and client all support,client supported methods:{:?}, server support methods:{:?}",
                auth_methods_from_client, SERVER_SUPPORTED_AUTHS
            );
            log::error!("{}", msg);
            return Err(anyhow!(msg));
        }
    };
    log::trace!("final authmethod:{:?}", &am);
    stream.write_all(&[SOCKS_VERSION, am.into()]).await?;

    if am.eq(&AuthMethod::NoAuth) {
        Ok(())
    } else {
        todo!("socks5支持其他认证方法")
    }
}

async fn bind_remote(stream: &mut TcpStream) -> Result<()> {
    valid_socks_ver(stream).await?;

    let mut response_builder = SocksResponse::builder();

    let cmd_buf = stream.read_u8().await?;
    let cmd = match Cmd::try_from(cmd_buf) {
        Ok(cmd) => cmd,
        Err(e) => return Err(e),
    };
    log::trace!("the client cmd is: {:?}", cmd);
    let _rsv = stream.read_u8().await?;
    let (atyp, address, port) = read_address(stream).await?;
    log::trace!(
        "read address success, atyp:{:?},address:{},port:{}",
        atyp,
        String::from_utf8_lossy(&address),
        port
    );
    response_builder
        .atyp(atyp)
        .dst_addr(address.clone())
        .dst_port(port);

    match cmd {
        Cmd::Connect => {
            let outbound = OutBoundFactory::get(OutBoundType::Ethan);
            let connect_request = ConnectRequest::try_from((atyp, address.as_slice(), port))?;
            let mut outbound_stream = outbound.connect_server(connect_request).await?;
            response_builder.rep(crate::socks5_proto::SocksResponseType::Success);
            let response = response_builder.build();
            let response = response.to_bytes();
            stream.write_all(&response).await?;
            stream.flush().await?;
            transfer_data(stream, &mut outbound_stream).await;
        }
        Cmd::Bind => todo!(),
        Cmd::Udp => todo!(),
    }

    Ok(())
}

async fn transfer_data(in_stream: &mut TcpStream, out_stream: &mut TcpStream) {
    log::trace!("starting transfer data");
    match tokio::io::copy_bidirectional(in_stream, out_stream).await {
        Ok(n) => {
            println!("copied {}:{} bites", n.0, n.1);
        }
        Err(err) => log::warn!("copied occured error, {}", err),
    }
}

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

async fn read_address(stream: &mut TcpStream) -> Result<(SocksAddressType, Vec<u8>, u16)> {
    let t = stream.read_u8().await?;
    match t {
        0x01 => {
            let mut buf = [0; 4];
            stream.read_exact(&mut buf).await?;
            let port = stream.read_u16().await?;
            Ok((SocksAddressType::Ipv4, buf.to_vec(), port))
        }
        0x03 => {
            let len = stream.read_u8().await.expect("get domain length") as usize;
            let mut domain = vec![0; len];
            stream.read_exact(&mut domain).await?;
            let port = stream.read_u16().await?;

            Ok((SocksAddressType::Domain, domain, port))
        }
        0x04 => {
            let mut buf = [0; 16];
            stream.read_exact(&mut buf).await?;
            let port = stream.read_u16().await?;
            Ok((SocksAddressType::Ipv6, buf.to_vec(), port))
        }
        _ => Err(anyhow!(format!("unkonw atyp: {}", t))),
    }
}