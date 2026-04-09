use std::{
    env,
    fs::File,
    io::BufReader,
    net::SocketAddr,
    path::{Path, PathBuf},
    sync::Arc,
};

use anyhow::{Result, anyhow};
use async_trait::async_trait;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
};
use tokio_rustls::rustls::ServerConfig;

use crate::{
    APP_CONFIG, EthanInBoundConfig,
    ethan::ethan_proto::{AuthRequest, ConnectRequest, EthanResponse},
    factory::outbound_factory::OutBoundFactory,
    traits::{async_read_write::AsyncReadWrite, proxy_inbound::InBoundProxy},
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
        log::info!("ethan server start listening at port: {}", port);
        while let Ok((stream, addr)) = listener.accept().await {
            let config = self.config.clone();
            //todo: 此处没有将正在处理的线程保存，所以在停止时可能会导致正在处理的数据丢失。
            //等待再次考虑
            let connector = EthanInBoundConnector::new(stream, addr, config);
            connector.handlstream().await;
        }
    }
}
struct EthanInBoundConnector {
    stream: TcpStream,
    remote_addr: SocketAddr,
    config: Arc<EthanInBoundConfig>,
}
impl EthanInBoundConnector {
    fn new(stream: TcpStream, remote_addr: SocketAddr, config: Arc<EthanInBoundConfig>) -> Self {
        Self {
            stream,
            remote_addr,
            config,
        }
    }

    async fn handlstream(mut self) {
        log::info!("ethan server rev connect, remote :{:?}", self.remote_addr);
        let config = self.config.clone();
        tokio::spawn(async move {
            if self.auth_handle().await.is_err() {
                log::error!("ethan server rev auth request, but failed!");
                return;
            }
            let mut out_stream = self.bind_handle().await.expect("bind to server failed");
            let tls_config = config.tls();
            let mut stream = {
                if tls_config.use_tls {
                    self.wraptls().await.unwrap()
                } else {
                    Box::new(self.stream)
                }
            };

            match tokio::io::copy_bidirectional(&mut *stream, &mut out_stream).await {
                Ok((n, m)) => {
                    log::trace!("copied {}:{} bites", n, m)
                }
                Err(err) => {
                    log::error!("data transfer broken out with error: {}", err);
                }
            }
        });
    }

    async fn auth_handle(&mut self) -> Result<()> {
        let config = self.config.clone();
        let lens = self.stream.read_u8().await? as usize;
        log::trace!("ethan server received client auth request,lens: {}", lens);
        let mut buff = vec![0u8; lens];
        self.stream.read_exact(&mut buff).await?;
        let request = AuthRequest::try_from(buff.as_slice())?;
        log::trace!("ethan server received client auth request: {:?}", request);
        let uid_in_config = config.uid();
        let pwd_in_config = config.pwd();
        if request.uid().eq(uid_in_config) && request.pwd().eq(pwd_in_config) {
            let response = EthanResponse::new(true, None);
            let response = response.as_bytes();
            self.stream.write_u8(response.len() as u8).await?;
            self.stream.write_all(response.as_slice()).await?;
            log::trace!("ethan server client auth uid and pwd is correct!");
            Ok(())
        } else {
            log::error!("ethan server client auth uid and pwd is incorrect!");
            let response = EthanResponse::new(true, Some("uid and pwd is incorrect".into()));
            let response = response.as_bytes();
            self.stream.write_u8(response.len() as u8).await?;
            self.stream.write_all(response.as_slice()).await?;
            Err(anyhow!("uid and pwd is incorrect"))
        }
    }

    async fn bind_handle(&mut self) -> Result<Box<dyn AsyncReadWrite + Send + Unpin>> {
        let lens = self.stream.read_u8().await? as usize;
        let mut buff = vec![0u8; lens];
        self.stream.read_exact(&mut buff).await?;
        let request = ConnectRequest::try_from(buff.as_slice())?;
        log::info!("received connect server: {:?}", request);

        let output_config = APP_CONFIG
            .get_forward_to_remote(&request)
            .expect("未找到匹配的路由");
        let output_bound = OutBoundFactory::get(&output_config);
        match output_bound.connect_server(request).await {
            Ok(out_stream) => {
                let response = EthanResponse::new(true, None);
                let bytes = response.as_bytes();
                self.stream.write_u8(bytes.len() as u8).await?;
                self.stream.write_all(&bytes).await?;
                Ok(out_stream)
            }
            Err(err) => {
                let response = EthanResponse::new(false, Some(err.to_string()));
                let bytes = response.as_bytes();
                self.stream.write_u8(bytes.len() as u8).await?;
                self.stream.write_all(&bytes).await?;
                Err(err)
            }
        }
    }

    async fn wraptls(self) -> Result<Box<dyn AsyncReadWrite + Unpin + Send>> {
        log::trace!("server start wrap tls!");
        let tls_config = self.config.tls();
        if tls_config.crt_path.is_none()
            || tls_config.key_path.is_none()
            || tls_config.domain_name.is_none()
        {
            return Err(anyhow!(
                "use tls, crt path, key path, domain name must has value"
            ));
        }
        let key_path = match tls_config.key_path {
            Some(ref k) => {
                let expanded = expand_path(k);
                log::trace!("key path:{}", expanded.display());
                if expanded.exists() {
                    expanded
                } else {
                    return Err(anyhow!("key path not found: {}", expanded.display()));
                }
            }
            None => return Err(anyhow!("key path can't null")),
        };
        let crt_path = match tls_config.crt_path {
            Some(ref k) => {
                let expanded = expand_path(k);
                log::trace!("crt path:{}", expanded.display());
                if expanded.exists() {
                    expanded
                } else {
                    return Err(anyhow!("crt path not found: {}", expanded.display()));
                }
            }
            None => return Err(anyhow!("crt path can't null")),
        };
        let _domain_name = match tls_config.domain_name {
            Some(ref d) => d.clone(),
            None => return Err(anyhow!("domain name can't null")),
        };

        let config = get_tsl_server_config(&crt_path, &key_path).await?;
        let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(config));
        let accept = acceptor.accept(self.stream).await?;
        log::trace!("server  wrap stream with tls success!");
        Ok(Box::new(accept))
    }
}

fn expand_path(path: &Path) -> PathBuf {
    let raw = path.to_string_lossy();
    if raw == "~" || raw.starts_with("~/") {
        if let Some(home) = env::var_os("HOME") {
            let mut expanded = PathBuf::from(home);
            if raw.len() > 2 {
                expanded.push(&raw[2..]);
            }
            return expanded;
        }
    } else if raw.starts_with("./") {
        let mut currentdir = env::current_dir().expect("get current dir failed!");
        currentdir.push(&raw[2..]);
        return currentdir;
    }
    path.to_path_buf()
}

async fn get_tsl_server_config(crt_path: &Path, key_path: &Path) -> Result<ServerConfig> {
    let fullchain = File::open(crt_path)?;
    let mut cert_reader = BufReader::new(fullchain);
    let cert_chain = rustls_pemfile::certs(&mut cert_reader).collect::<Vec<_>>();
    let mut certs = Vec::with_capacity(cert_chain.len());
    for ct in cert_chain.into_iter().flatten() {
        certs.push(ct);
    }

    let key = File::open(key_path)?;
    let mut key_reader = BufReader::new(key);
    let priv_key = rustls_pemfile::private_key(&mut key_reader)?;
    let priv_key = match priv_key {
        Some(pk) => pk,
        None => {
            return Err(anyhow!("not found private key"));
        }
    };
    let config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, priv_key)?;
    Ok(config)
}

#[cfg(test)]
mod test {
    use std::env;

    use super::*;

    #[tokio::test]
    async fn load_tls_server_config_test() -> Result<()> {
        let base_path = env::current_dir()?;
        let fullchain_path = base_path.join("examples/certs/fullchain.pem");
        let key_path = base_path.join("examples/certs/privkey.pem");

        let _config = get_tsl_server_config(&fullchain_path, &key_path).await?;
        Ok(())
    }

    #[test]
    fn expand_path_test() {
        let final_path = expand_path(Path::new("./file.json"));
        assert!(final_path.display().to_string().chars().count()>"/file.json".chars().count());
        println!("{}",final_path.display());
    }
}
