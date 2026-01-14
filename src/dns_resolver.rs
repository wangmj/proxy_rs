use anyhow::{Result, anyhow};
use hickory_resolver::Resolver;
use std::net::IpAddr;
use tokio::net::TcpStream;

pub async fn resolve_dns(domain_name: &str) -> Result<Vec<IpAddr>> {
    if !is_valid_domain(domain_name) {
        return Err(anyhow!("Unvalid domain name"));
    }
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

/// 辅助方法：校验域名合法性（符合DNS核心规范）
 fn is_valid_domain(domain: &str) -> bool {
    // 规则1：域名总长度不超过253个字符（DNS规范）
    if domain.len() > 253 {
        return false;
    }

    // 规则2：拆分域名标签（以.分隔，如www.baidu.com拆分为[www, baidu, com]）
    let labels: Vec<&str> = domain.split('.').collect();
    if labels.is_empty() || labels.iter().any(|label| label.is_empty()) {
        return false; // 避免空标签（如www..baidu.com）
    }

    // 规则3：每个标签的长度不超过63个字符（DNS规范）
    if labels.iter().any(|label| label.len() > 63) {
        return false;
    }

    // 规则4：合法字符校验（a-z, A-Z, 0-9, -，且不能以-开头/结尾）
    let valid_char = |c: char| c.is_ascii_alphanumeric() || c == '-';

    for label in labels {
        // 标签不能为空，且不能以-开头或结尾
        if label.starts_with('-') || label.ends_with('-') {
            return false;
        }

        // 标签内所有字符均需合法
        if !label.chars().all(valid_char) {
            return false;
        }
    }

    // 所有规则均满足
    true
}
