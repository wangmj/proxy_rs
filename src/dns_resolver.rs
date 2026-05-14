use anyhow::{Result, anyhow};
use hickory_resolver::{
    Resolver,
    config::{NameServerConfig, ResolverConfig, ResolverOpts},
    name_server::{GenericConnector, TokioConnectionProvider},
    proto::{runtime::TokioRuntimeProvider, xfer::Protocol},
};
use std::{
    net::{IpAddr, SocketAddr},
    str::FromStr,
    sync::LazyLock,
    time::Duration,
};
use tokio::net::TcpStream;

use crate::APP_CONFIG;

pub(crate) async fn resolve_dns_pick_fastet(domain_name: impl AsRef<str>) -> Result<IpAddr> {
    match resolve_dns(domain_name).await {
        Ok(ipaddrs) => match pick_fastet_ip_with_ping(&ipaddrs).await {
            Some(ipaddr) => Ok(ipaddr),
            None => Err(anyhow!("not found fastet ip")),
        },
        Err(err) => Err(anyhow!("{err}")),
    }
}

static DNS_RESOVLER: LazyLock<Resolver<GenericConnector<TokioRuntimeProvider>>> =
    LazyLock::new(get_dns_resolver);

fn get_dns_resolver() -> Resolver<GenericConnector<TokioRuntimeProvider>> {
    let mut opts = ResolverOpts::default();
    opts.num_concurrent_reqs = 50;
    opts.timeout = Duration::from_secs(3);
    opts.attempts = 1;
    // opts.use_hosts_file = hickory_resolver::config::ResolveHosts:;
    opts.edns0 = false;
    let mut resolver_config = ResolverConfig::new();
    match &APP_CONFIG.dns().server {
        Some(ss) if !ss.is_empty() => {
            ss.iter()
                .map_while(|item| {
                    if !item.contains(":") {
                        SocketAddr::from_str(format!("{item}:53").as_str()).ok()
                    } else {
                        SocketAddr::from_str(item).ok()
                    }
                })
                .for_each(|item| {
                    let tmp = NameServerConfig::new(item, Protocol::Udp);
                    resolver_config.add_name_server(tmp);
                });
            if !resolver_config.name_servers().is_empty() {
                opts.use_hosts_file = hickory_resolver::config::ResolveHosts::Never;
            } else {
                log::error!(
                    r#"因配置的dns 服务器 格式不正确，无法使用，转而使用系统的，正确格式例子:["8.8.8.8:53","8.8.8.8"]"#
                );
                opts.use_hosts_file = hickory_resolver::config::ResolveHosts::Always;
            }
        }
        _ => {
            (resolver_config,opts)=hickory_resolver::system_conf::read_system_conf().expect("failed read system dns config");
            // opts.use_hosts_file = hickory_resolver::config::ResolveHosts::Always;
        }
    }
    Resolver::builder_with_config(resolver_config, TokioConnectionProvider::default())
        .with_options(opts)
        .build()
}

pub async fn resolve_dns(domain_name: impl AsRef<str>) -> Result<Vec<IpAddr>> {
    let domain_name = domain_name.as_ref();
    if !is_valid_domain(domain_name) {
        return Err(anyhow!("Unvalid domain name"));
    }
    let domain_name = match domain_name.ends_with(".") {
        true => domain_name.to_string(),
        false => format!("{}.", domain_name),
    };
    let response = DNS_RESOVLER.lookup_ip(domain_name).await.unwrap();
    let mut res = Vec::new();
    for ip in response.iter() {
        res.push(ip);
    }
    Ok(res)
}

pub async fn pick_fastet_ip_with_ping(addrs: &[IpAddr]) -> Option<IpAddr> {
    if addrs.len().eq(&0) {
        return None;
    }
    if addrs.len().eq(&1) {
        return Some(addrs[0]);
    }
    let mut task_set = tokio::task::JoinSet::new();
    for &ip in addrs {
        task_set.spawn(async move {
            let mut rtt_list = Vec::new();
            for _ in 0..5 {
                match ping::new(ip).send() {
                    Ok(res) => rtt_list.push(res.rtt),
                    Err(_) => {
                        rtt_list.push(Duration::from_secs(60));
                    }
                }
            }
            let speed =
                rtt_list.iter().map(|x| x.as_millis()).sum::<u128>() / (rtt_list.len() as u128);
            (ip, speed)
        });
    }
    let res = task_set.join_all().await;
    res.iter().min_by_key(|&x| x.1).map(|x| x.0)
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
