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
    app_config::{EthanOutBoundConfig, TlsClientConfig},
    ethan::ethan_proto::{AuthRequest, ConnectRequest, DstType, EthanResponse},
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
        let addr = self.config.socket_addr().await?;
        let mut stream = TcpStream::connect(addr).await?;
        auth_request(&mut stream, self.config.clone()).await?;
        bind_request(
            &mut stream,
            connect_request.port(),
            connect_request.dst_type(),
        )
        .await?;

        let tls_config = self.config.tls();
        let stream2 = {
            if tls_config.use_tls {
                wraptls(stream, tls_config).await?
            } else {
                Box::new(stream)
            }
        };

        Ok(stream2)
    }
}
async fn auth_request(stream: &mut TcpStream, config: Arc<EthanOutBoundConfig>) -> Result<()> {
    log::trace!("ethan client start auth with server");

    let auth_request = AuthRequest::new(config.uid().to_string(), config.pwd().to_string());
    let auth_bytes = auth_request.as_bytes();
    stream.write_u8(auth_bytes.len() as u8).await?;
    stream.write_all(&auth_bytes).await?;
    log::trace!("ethan client send auth to server");

    let len = stream.read_u8().await? as usize;
    let mut buff = vec![0u8; len];
    stream.read_exact(&mut buff).await?;
    log::trace!("ethan client received server auth response");
    let response = EthanResponse::try_from(&buff[..])?;
    if response.res() {
        log::trace!("ethan client received server auth response: success");
        Ok(())
    } else {
        Err(anyhow!(
            "auth failed. err: {}",
            response
                .reason()
                .as_deref()
                .unwrap_or("server not return auth failed reason")
        ))
    }
}

async fn bind_request(stream: &mut TcpStream, port: u16, dst: &DstType) -> Result<()> {
    let ccmd = ConnectRequest::new(port, dst.clone());
    let ccmd_bytes = ccmd.as_bytes();
    stream.write_u8(ccmd_bytes.len() as u8).await?;
    stream.write_all(&ccmd_bytes).await?;

    let len = stream.read_u8().await?;
    let mut buff = vec![0u8; len as usize];
    stream.read_exact(&mut buff).await?;
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

async fn wraptls(
    stream: TcpStream,
    tls_config: &TlsClientConfig,
) -> Result<Box<dyn AsyncReadWrite + Send + Unpin>> {
    log::trace!("client start wrap tls");
    let domain_name = match tls_config.domain_name {
        Some(ref d) => d,
        None => return Err(anyhow!("domain name can't be null")),
    };
    let mut root_cert_store =
        RootCertStore::from_iter(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    if let Some(ref crt_path) = tls_config.crt_path
        && !crt_path.to_string_lossy().is_empty()
    {
        let cert = CertificateDer::from_pem_file(crt_path)?;
        root_cert_store.add(cert)?;
    }

    let config = rustls::ClientConfig::builder()
        .with_root_certificates(Arc::new(root_cert_store))
        .with_no_client_auth();
    let connector = TlsConnector::from(Arc::new(config));

    let domain_name =
        ServerName::try_from(domain_name.to_string()).expect("domain name is incorrect");
    let stream = connector.connect(domain_name, stream).await?;
    log::trace!("client wrap straem with tls success!");
    Ok(Box::new(stream))
}
