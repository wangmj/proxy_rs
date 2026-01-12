use anyhow::Result;
use hickory_resolver::Resolver;
use std::net::IpAddr;
use tokio::net::TcpStream;

pub async fn resolve_dns(domain_name: &str) -> Result<Vec<IpAddr>> {
    let resolver = Resolver::builder_tokio()?.build();
    let domain_name = match domain_name.ends_with(".") {
        true => domain_name.to_string(),
        false => format!("{}.", domain_name),
    };
    let response = resolver.lookup_ip(domain_name).await.unwrap();
    let mut res = Vec::new();
    for ip in response.iter() {
        res.push(ip);
    }
    Ok(res)
}

pub async fn pick_fastet_ipadd(addrs: &[IpAddr], port: u16) -> Option<IpAddr> {
    if addrs.len().eq(&0) {
        return None;
    }
    if addrs.len().eq(&1) {
        return Some(addrs[0]);
    }

    let mut result = Vec::with_capacity(addrs.len());
    for ip in addrs {
        let start = std::time::Instant::now();
        let addr = (*ip, port);
        if TcpStream::connect(addr).await.is_ok() {
            result.push((start.elapsed(), *ip));
        }
    }

    result.sort_by(|x1, x2| x1.0.cmp(&x2.0));
    result.into_iter().next().map(|x| x.1)
}
