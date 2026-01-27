use std::{fs::File, io::BufReader, net::SocketAddr, path::Path, sync::Arc};

use anyhow::{Result, anyhow};
use async_trait::async_trait;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
};
use tokio_rustls::rustls::{
    ServerConfig,
};

use crate::{
    APP_CONFIG, EthanInBoundConfig, TlsServerConfig,
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
        log::trace!("ethan server start listening at port: {}", port);
        let config = self.config.clone();
        while let Ok((stream, addr)) = listener.accept().await {
            //todo: 此处没有将正在处理的线程保存，所以在停止时可能会导致正在处理的数据丢失。
            //等待再次考虑
            handlstream(stream, addr, config.clone()).await;
        }
    }
}
async fn handlstream(mut stream: TcpStream, addr: SocketAddr, config: Arc<EthanInBoundConfig>) {
    log::trace!("ethan server rev connect, remote :{:?}", addr);
    let config = config.clone();
    tokio::spawn(async move {
        if auth_handle(&mut stream, config.clone()).await.is_err() {
            log::error!("ethan server rev auth request, but failed!");
            return;
        }
        let mut out_stream = bind_handle(&mut stream)
            .await
            .expect("bind to server failed");
        let tls_config = config.tls();
        let mut stream = {
            if tls_config.use_tls {
                wraptls(stream, tls_config).await.unwrap()
            } else {
                Box::new(stream)
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

async fn auth_handle(stream: &mut TcpStream, config: Arc<EthanInBoundConfig>) -> Result<()> {
    let lens = stream.read_u8().await? as usize;
    log::trace!("ethan server received client auth request,lens: {}", lens);
    let mut buff = vec![0u8; lens];
    stream.read_exact(&mut buff).await?;
    let request = AuthRequest::try_from(buff.as_slice())?;
    log::trace!("ethan server received client auth request: {:?}", request);
    let uid_in_config = config.uid();
    let pwd_in_config = config.pwd();
    if request.uid().eq(uid_in_config) && request.pwd().eq(pwd_in_config) {
        let response = EthanResponse::new(true, None);
        let response = response.as_bytes();
        stream.write_u8(response.len() as u8).await?;
        stream.write_all(response.as_slice()).await?;
        log::trace!("ethan server client auth uid and pwd is correct!");
        Ok(())
    } else {
        log::error!("ethan server client auth uid and pwd is incorrect!");
        let response = EthanResponse::new(true, Some("uid and pwd is incorrect".into()));
        let response = response.as_bytes();
        stream.write_u8(response.len() as u8).await?;
        stream.write_all(response.as_slice()).await?;
        Err(anyhow!("uid and pwd is incorrect"))
    }
}

async fn bind_handle(in_stream: &mut TcpStream) -> Result<Box<dyn AsyncReadWrite + Send + Unpin>> {
    let lens = in_stream.read_u8().await? as usize;
    let mut buff = vec![0u8; lens];
    in_stream.read_exact(&mut buff).await?;
    let request = ConnectRequest::try_from(buff.as_slice())?;

    let output_bound = OutBoundFactory::get(APP_CONFIG.outbound());
    match output_bound.connect_server(request).await {
        Ok(out_stream) => {
            let response = EthanResponse::new(true, None);
            let bytes = response.as_bytes();
            in_stream.write_u8(bytes.len() as u8).await?;
            in_stream.write_all(&bytes).await?;
            Ok(out_stream)
        }
        Err(err) => {
            let response = EthanResponse::new(false, Some(err.to_string()));
            let bytes = response.as_bytes();
            in_stream.write_u8(bytes.len() as u8).await?;
            in_stream.write_all(&bytes).await?;
            Err(err)
        }
    }
}

async fn wraptls(
    stream: TcpStream,
    tls_config: &TlsServerConfig,
) -> Result<Box<dyn AsyncReadWrite + Unpin + Send>> {
    log::trace!("server start wrap tls!");
    if tls_config.crt_path.is_none()
        || tls_config.key_path.is_none()
        || tls_config.domain_name.is_none()
    {
        return Err(anyhow!(
            "use tls, crt path, key path, domain name must has value"
        ));
    }
    let key_path = match tls_config.key_path {
        Some(ref k) => k.clone(),
        None => return Err(anyhow!("key path can't null")),
    };
    let crt_path = match tls_config.crt_path {
        Some(ref k) => k.clone(),
        None => return Err(anyhow!("crt path can't null")),
    };
    let _domain_name = match tls_config.domain_name {
        Some(ref d) => d.clone(),
        None => return Err(anyhow!("domain name can't null")),
    };
    
    let config= get_tsl_server_config(&crt_path,&key_path).await?;
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(config));
    let accept = acceptor.accept(stream).await?;
    log::trace!("server  wrap stream with tls success!");
    Ok(Box::new(accept))
}

async fn get_tsl_server_config(crt_path: &Path, key_path: &Path) -> Result<ServerConfig> {
    let fullchain = File::open(crt_path)?;
    let mut cert_reader = BufReader::new(fullchain);
    let cert_chain = rustls_pemfile::certs(&mut cert_reader).into_iter().collect::<Vec<_>>();
    let mut certs = Vec::with_capacity(cert_chain.len());
    for ct in cert_chain {
        if let Ok(c) = ct {
            certs.push(c);
        }
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
    use std::{
        env,
    };


    use super::*;

    #[tokio::test]
    #[ignore = "pem file is store only at local dev"]
    async fn load_tls_server_config_test() -> Result<()> {
        let base_path = env::current_dir()?;
        let fullchain_path = base_path.join("examples/certs/fullchain.pem");
        let key_path = base_path.join("examples/certs/privkey.pem");

        let _config= get_tsl_server_config(&fullchain_path,&key_path).await?;

        // println!("{}", fullchain_path.display());
        // let fullchain = File::open(fullchain_path)?;
        // let mut cert_reader = BufReader::new(fullchain);
        // let cert_chain = certs(&mut cert_reader).into_iter().collect::<Vec<_>>();
        // let mut certs = Vec::with_capacity(cert_chain.len());
        // for ct in cert_chain {
        //     if let Ok(c) = ct {
        //         certs.push(c);
        //     }
        // }

        
        // println!("{}", key_path.display());

        // let key = File::open(key_path)?;
        // let mut key_reader = BufReader::new(key);
        // let priv_key = rustls_pemfile::private_key(&mut key_reader)?;
        // let priv_key = match priv_key {
        //     Some(pk) => pk,
        //     None => {
        //         return Err(anyhow!("not found private key"));
        //     }
        // };
        // let _config = ServerConfig::builder()
        //     .with_no_client_auth()
        //     .with_single_cert(certs, priv_key)?;

        Ok(())
    }
}
