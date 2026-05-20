use std::{pin::Pin, sync::Arc};

use anyhow::Result;
use async_trait::async_trait;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
};
use tokio_rustls::{
    TlsConnector,
    rustls::{
        self, RootCertStore,
        pki_types::{CertificateDer, ServerName, pem::PemObject},
    },
};
use webpki_roots;

use crate::{
    ProxyError,
    app_config::EthanOutBoundConfig,
    ethan::ethan_proto::{AuthRequest, ConnectRequest, EthanResponse},
    traits::proxy_outbound::{AsyncReadWriteStream, OutBoundProxy},
    utils,
};

pub struct EthanOutBound {
    config: Arc<EthanOutBoundConfig>,
}

impl EthanOutBound {
    pub(crate) fn new(config: Arc<EthanOutBoundConfig>) -> Self {
        Self { config }
    }
}

#[async_trait]
impl OutBoundProxy for EthanOutBound {
    async fn connect_server(
        &self, connect_request: ConnectRequest,
    ) -> Result<AsyncReadWriteStream> {
        let connector = EthanOutBoundConnector::new(self.config.clone(), connect_request).await?;
        connector.build_connect().await
    }
}

struct EthanOutBoundConnector {
    config: Arc<EthanOutBoundConfig>,
    stream: AsyncReadWriteStream,
    connect_request: ConnectRequest,
}
impl EthanOutBoundConnector {
    pub async fn new(
        config: Arc<EthanOutBoundConfig>, connect_request: ConnectRequest,
    ) -> Result<Self> {
        let addr = config.socket_addr().await?;
        let stream = TcpStream::connect(addr).await?;
        let stream = Box::pin(stream) as Pin<_>;
        Ok(Self { config, stream, connect_request })
    }
    pub async fn build_connect(mut self) -> Result<AsyncReadWriteStream> {
        self.wraptls().await?;
        self.auth_request().await?;
        self.bind_request().await?;
        Ok(self.stream)
    }

    async fn auth_request(&mut self) -> Result<()> {
        log::info!("ethan client start auth with server");

        let auth_request =
            AuthRequest::new(self.config.uid().to_string(), self.config.pwd().to_string());
        let auth_bytes = auth_request.into_bytes();

        let locked_stream = &mut self.stream;
        locked_stream.write_u8(auth_bytes.len() as u8).await?;
        locked_stream.write_all(&auth_bytes).await?;
        locked_stream.flush().await?;

        log::trace!("ethan client had send auth info to server, and then wait server");

        let len = locked_stream.read_u8().await? as usize;
        let mut buff = vec![0u8; len];
        locked_stream.read_exact(&mut buff).await?;

        log::trace!("ethan client received server auth response");

        let response = EthanResponse::try_from(&buff[..])?;

        if response.res() {
            log::info!("ethan client received server auth response: success");
            Ok(())
        } else {
            let reason = response
                .reason()
                .as_ref()
                .cloned()
                .unwrap_or("server not return auth failed reason".into());
            Err(ProxyError::EthanAuthFailed(reason).into())
        }
    }

    async fn bind_request(&mut self) -> Result<()> {
        let ccmd_bytes = self.connect_request.as_bytes();

        let locked_stream = &mut self.stream;
        locked_stream.write_u8(ccmd_bytes.len() as u8).await?;
        locked_stream.write_all(&ccmd_bytes).await?;

        let len = locked_stream.read_u8().await?;
        let mut buff = vec![0u8; len as usize];
        locked_stream.read_exact(&mut buff).await?;
        let response = EthanResponse::try_from(&buff[..])?;
        if response.res() {
            Ok(())
        } else {
            let reason = response
                .reason()
                .as_ref()
                .cloned()
                .unwrap_or("server not return auth failed reason".into());
            Err(ProxyError::EthanBindError(reason).into())
        }
    }

    async fn wraptls(&mut self) -> Result<()> {
        let tls_config = self.config.tls();
        if let Some(tls_config) = tls_config {
            log::trace!("client start wrap tls");

            let domain_name = self.config.addr();
            let mut root_cert_store =
                RootCertStore::from_iter(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());

            if !&tls_config.crt_path.as_os_str().is_empty() {
                let tls_crt_path = utils::expand_path(&tls_config.crt_path);
                if tls_crt_path.exists() {
                    let reader =
                        tokio::fs::File::open(&tls_config.crt_path).await?.into_std().await;
                    let cert = CertificateDer::from_pem_reader(reader)?;
                    root_cert_store.add(cert)?;
                }else{
                    log::warn!("文件：{} 不存在",&tls_config.crt_path.display());
                }
            }

            let config = rustls::ClientConfig::builder()
                .with_root_certificates(Arc::new(root_cert_store))
                .with_no_client_auth();
            let connector = TlsConnector::from(Arc::new(config));

            let server_name =
                ServerName::try_from(domain_name.to_string()).expect("domain name is incorrect");

            //使用mem::replace换出原来的tcpStream，避免后面修改已借用的值。
            //还有一种方法，使用Option+take
            let old_stream = std::mem::replace(&mut self.stream, Box::pin(tokio::io::empty()));
            let stream = connector
                .connect(server_name, old_stream)
                .await
                .map_err(ProxyError::TlsHandshakeError)?;
            self.stream = Box::pin(stream);

            log::trace!("client wrap straem with tls success!");
        }
        Ok(())
    }
}
