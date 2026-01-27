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
    DNSResolver,
    app_config::EthanOutBoundConfig,
    dns_resolver::{pick_fastet_ipadd, resolve_dns},
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
        let connector = OutBoundConnectorRequest::new(self.config.clone(), connect_request).await?;
        connector.build_connect().await
    }
}
struct OutBoundConnectorRequest {
    config: Arc<EthanOutBoundConfig>,
    stream: TcpStream,
    connect_request: ConnectRequest,
}
impl OutBoundConnectorRequest {
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
        log::trace!("ethan client start auth with server");

        let auth_request =
            AuthRequest::new(self.config.uid().to_string(), self.config.pwd().to_string());
        let auth_bytes = auth_request.as_bytes();
        self.stream.write_u8(auth_bytes.len() as u8).await?;
        self.stream.write_all(&auth_bytes).await?;
        log::trace!("ethan client send auth to server");

        let len = self.stream.read_u8().await? as usize;
        let mut buff = vec![0u8; len];
        self.stream.read_exact(&mut buff).await?;
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

    async fn bind_request(&mut self) -> Result<()> {
        let mut dst = self.connect_request.dst_type().clone();
        if let DstType::DomainName(ref ds) = dst
            && let DNSResolver::Local = self.config.dns().resolver
        {
            let ips = resolve_dns(ds).await?;
            let ip = pick_fastet_ipadd(&ips, self.connect_request.port())
                .await
                .ok_or_else(|| anyhow!(format!("can't resolve dns:{} to ip", ds)))?;
            match ip {
                std::net::IpAddr::V4(ipv4_addr) => dst = DstType::Ipv4(ipv4_addr),
                std::net::IpAddr::V6(ipv6_addr) => dst = DstType::Ipv6(ipv6_addr),
            }
        }
        let ccmd = ConnectRequest::new(self.connect_request.port(), dst);
        let ccmd_bytes = ccmd.as_bytes();
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
        let stream = connector.connect(domain_name, self.stream).await?;
        log::trace!("client wrap straem with tls success!");
        Ok(Box::new(stream))
    }
}
