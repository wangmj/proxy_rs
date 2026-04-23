use std::sync::Arc;

use anyhow::{Result, anyhow};
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
    app_config::EthanOutBoundConfig,
    ethan::ethan_proto::{AuthRequest, ConnectRequest, EthanResponse},
    traits::{async_read_write::AsyncReadWrite, proxy_outbound::OutBoundProxy},
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
        &self,
        connect_request: ConnectRequest,
    ) -> Result<Box<dyn AsyncReadWrite + Unpin + Send>> {
        let connector = EthanOutBoundConnector::new(self.config.clone(), connect_request).await?;
        connector.build_connect().await
    }
}
struct EthanOutBoundConnector {
    config: Arc<EthanOutBoundConfig>,
    stream: TcpStream,
    connect_request: ConnectRequest,
}
impl EthanOutBoundConnector {
    pub async fn new(
        config: Arc<EthanOutBoundConfig>,
        connect_request: ConnectRequest,
    ) -> Result<Self> {
        let addr = config.socket_addr().await?;
        let stream = TcpStream::connect(addr).await?;
        Ok(Self {
            config,
            stream,
            connect_request,
        })
    }
    pub async fn build_connect(mut self) -> Result<Box<dyn AsyncReadWrite + Unpin + Send>> {
        self.auth_request().await?;
        self.bind_request().await?;
        self.wraptls().await
    }

    async fn auth_request(&mut self) -> Result<()> {
        log::info!("ethan client start auth with server");

        let auth_request =
            AuthRequest::new(self.config.uid().to_string(), self.config.pwd().to_string());
        let auth_bytes = auth_request.as_bytes();
        self.stream.write_u8(auth_bytes.len() as u8).await?;
        self.stream.write_all(&auth_bytes).await?;

        log::trace!("ethan client had send auth info to server, and then wait server");

        let len = self.stream.read_u8().await? as usize;
        let mut buff = vec![0u8; len];
        self.stream.read_exact(&mut buff).await?;

        log::trace!("ethan client received server auth response");

        let response = EthanResponse::try_from(&buff[..])?;
        if response.res() {
            log::info!("ethan client received server auth response: success");
            Ok(())
        } else {
            log::error!(
                "ethan client auth failed. the reason is: {}",
                response
                    .reason()
                    .as_deref()
                    .unwrap_or("server not return auth failed reason")
            );
            Err(anyhow!(
                "ethan client auth failed. the reason is: {}",
                response
                    .reason()
                    .as_deref()
                    .unwrap_or("server not return auth failed reason")
            ))
        }
    }

    async fn bind_request(&mut self) -> Result<()> {
        let ccmd_bytes = self.connect_request.as_bytes();
        self.stream.write_u8(ccmd_bytes.len() as u8).await?;
        self.stream.write_all(&ccmd_bytes).await?;

        let len = self.stream.read_u8().await?;
        let mut buff = vec![0u8; len as usize];
        self.stream.read_exact(&mut buff).await?;
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

    async fn wraptls(self) -> Result<Box<dyn AsyncReadWrite + Send + Unpin>> {
        let tls_config = self.config.tls();
        if let Some(tls_config) = tls_config {
            log::trace!("client start wrap tls");

            let domain_name = &tls_config.domain_name;
            let mut root_cert_store =
                RootCertStore::from_iter(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
            if !tls_config.crt_path.to_string_lossy().is_empty() {
                let cert = CertificateDer::from_pem_file(&tls_config.crt_path)?;
                root_cert_store.add(cert)?;
            }

            let config = rustls::ClientConfig::builder()
                .with_root_certificates(Arc::new(root_cert_store))
                .with_no_client_auth();
            let connector = TlsConnector::from(Arc::new(config));

            let server_name =
                ServerName::try_from(domain_name.to_string()).expect("domain name is incorrect");

            let stream = connector
                .connect(server_name, self.stream)
                .await
                .map_err(|e| {
                    log::error!("hanle tls stream error: {:?}", e);
                    anyhow!(e)
                })?;

            log::trace!("client wrap straem with tls success!");
            Ok(Box::new(stream) as Box<_>)
        } else {
            Ok(Box::new(self.stream) as Box<_>)
        }
    }
}
