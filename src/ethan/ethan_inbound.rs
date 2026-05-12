use std::{
    io::BufReader,
    net::SocketAddr,
    path::Path,
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
    APP_CONFIG, EthanInBoundConfig, ProxyError,
    ethan::ethan_proto::{AuthRequest, ConnectRequest, EthanResponse},
    factory::outbound_factory::OutBoundFactory,
    traits::{async_read_write::AsyncReadWrite, proxy_inbound::InBoundProxy},
    utils::expand_path,
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
            tokio::spawn(async move {
                let connector = EthanInBoundConnector::new(stream, addr, config);
                if let Err(err) = connector.handlstream().await {
                    log::error!("ethan inbound handle stream occur exception, {err}");
                }
            });
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

    async fn handlstream(mut self) -> Result<()> {
        log::trace!("ethan server rev connect, remote :{:?}", self.remote_addr);
        self.auth_handle().await?;
        let mut out_stream = self.bind_handle().await?;
        let mut stream = self.wraptls().await?;

        match tokio::io::copy_bidirectional(&mut *stream, &mut out_stream).await {
            Ok((n, m)) => {
                log::trace!("copied {}:{} bites", n, m);
                Ok(())
            }
            Err(err) => {
                log::error!("data transfer broken out with error: {}", err);
                Err(err.into())
            }
        }
    }

    async fn auth_handle(&mut self) -> Result<()> {
        //read lens
        let len = self.stream.read_u8().await? as usize;
        log::trace!("ethan server received client auth request,lens: {}", len);
        //read auth buff
        let mut buff = vec![0u8; len];
        self.stream.read_exact(&mut buff).await?;
        let request = AuthRequest::try_from(buff.as_slice())?;
        log::trace!("ethan server received client auth request: {:?}", request);

        let uid_in_config = self.config.uid();
        let pwd_in_config = self.config.pwd();

        //check uid and pwd is correct
        let (response, result) =
            if request.uid().eq(uid_in_config) && request.pwd().eq(pwd_in_config) {
                let response = EthanResponse::new(true, None);
                (response, Ok(()))
            } else {
                log::error!("ethan server client auth uid and pwd is incorrect!");
                let response = EthanResponse::new(true, Some("uid and pwd is incorrect".into()));
                (
                    response,
                    Err(ProxyError::EthanAuthUserPwdIncorrect(
                        request.uid().into(),
                        request.pwd().into(),
                    )
                    .into()),
                )
            };

        let response = response.as_bytes();
        self.stream.write_u8(response.len() as u8).await?;
        self.stream.write_all(response.as_slice()).await?;
        result
    }

    async fn bind_handle(&mut self) -> Result<Box<dyn AsyncReadWrite + Send + Unpin>> {
        let len = self.stream.read_u8().await? as usize;
        let mut buff = vec![0u8; len];
        self.stream.read_exact(&mut buff).await?;
        let request = ConnectRequest::try_from(buff.as_slice())?;
        log::trace!("received connect server: {:?}", request);

        let output_config = APP_CONFIG
            .get_forward_to_remote(&request)
            .await
            .expect("未找到匹配的路由");
        let output_bound = OutBoundFactory::get(&output_config);
        let (response, result) = match output_bound.connect_server(request).await {
            Ok(out_stream) => {
                let response = EthanResponse::new(true, None);
                (response, Ok(out_stream))
            }
            Err(err) => {
                let response = EthanResponse::new(false, Some(err.to_string()));
                (response, Err(err))
            }
        };
        let bytes = response.into_response_bytes();
        self.stream.write_all(&bytes).await?;
        result
    }

    async fn wraptls(self) -> Result<Box<dyn AsyncReadWrite + Unpin + Send>> {
        match self.config.tls() {
            None => Ok(Box::new(self.stream) as Box<_>),
            Some(tls_config) => {
                log::trace!("server start wrap tls!");

                let config = get_tsl_server_config(&tls_config.crt_path, &tls_config.key_path).await?;
                let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(config));
                let accept = acceptor.accept(self.stream).await?;
                log::trace!("server  wrap stream with tls success!");
                Ok(Box::new(accept) as Box<_>)
            }
        }
    }
}

async fn get_tsl_server_config(crt_path: &Path, key_path: &Path) -> Result<ServerConfig> {
    let crt_path_expanded = expand_path(crt_path);
    if !crt_path_expanded.exists() {
        return Err(anyhow!(
            "crt path not found: {}",
            crt_path_expanded.display()
        ));
    }

    let key_path_expanded = expand_path(key_path);
    if !key_path_expanded.exists() {
        return Err(anyhow!(
            "key path not found: {}",
            key_path_expanded.display()
        ));
    }
    let fullchain = tokio::fs::File::open(crt_path_expanded).await?;
    let mut cert_reader = BufReader::new(fullchain.into_std().await);
    let cert_chain = rustls_pemfile::certs(&mut cert_reader).collect::<Vec<_>>();
    let mut certs = Vec::with_capacity(cert_chain.len());
    for ct in cert_chain.into_iter().flatten() {
        certs.push(ct);
    }

    let key = tokio::fs::File::open(key_path_expanded).await?.into_std().await;
    let mut key_reader = BufReader::new(key);
    let priv_key = rustls_pemfile::private_key(&mut key_reader)?;
    let priv_key = priv_key.ok_or_else(|| anyhow!("not found private key"))?;
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
}
