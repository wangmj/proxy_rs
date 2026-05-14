use anyhow::{Result, anyhow};
use bytes::{Buf, BufMut, BytesMut};
use std::{
    fmt::Display,
    mem,
    net::{Ipv4Addr, Ipv6Addr},
};

use crate::{ProxyError, socks::socks5_proto::SocksAddressType};

///连接请求
// 本来实现是想实现零拷贝类型的，但经过思考及探索，发现不可避免都要拷贝，原因是：
// 1.该类型总会持有数据，因为从接入的请求中读取出的数据存在缓存中，这些数据继续放在缓存中不合适，只能是该类型持有这些数据，这个过程实现的是move，但由于是u8的数组，大部分的时候是copy
// 2.该类型使用过程中，需要多次返回一些请求的类型DstType，如果不持有数据，则无法返回DstType的引用，并且每次返回都需要构造，与其这样，还不如直接持有数据，返回DstType的引用合适
// 3.之前考虑过直接使用ConnectRequest(Vec<u8>)的实现，原因是这样会实现From<u8>和as_bytes会更加便捷，但由于上面的原因会产生多次copy，而as_bytes改为into_bytes，只会产生一次移动，因此综合考虑还是使用这种实现
#[derive(Debug, PartialEq, Clone)]
pub(crate) struct ConnectRequest {
    dst_port: u16,
    dst_type: DstType,
}

///目标地址类型
#[derive(Debug, PartialEq, Clone)]
pub(crate) enum DstType {
    Ipv4(Ipv4Addr),
    Ipv6(Ipv6Addr),
    DomainName(String),
}
impl DstType {
    pub fn len(&self) -> usize {
        match self {
            DstType::Ipv4(_) => mem::size_of::<Ipv4Addr>() + 1,
            DstType::Ipv6(_) => mem::size_of::<Ipv6Addr>() + 1,
            DstType::DomainName(str) => str.len() + 2,
        }
    }
    // pub fn into_bytes(self) -> Vec<u8> {
    //     let mut v = Vec::with_capacity(self.len());
    //     match self {
    //         DstType::Ipv4(ipv4_addr) => {
    //             v.put_u8(1);
    //             v.put_u32(ipv4_addr.to_bits());
    //             v
    //         }
    //         DstType::Ipv6(ipv6_addr) => {
    //             v.put_u8(2);
    //             v.put_u128(ipv6_addr.to_bits());
    //             v
    //         }
    //         DstType::DomainName(str) => {
    //             assert!(str.len() < u8::MAX as usize);

    //             v.put_u8(3);
    //             v.put_u8(str.len() as u8);
    //             v.put(str.as_bytes());
    //             v
    //         }
    //     }
    // }

    pub fn from_bytes(val: &[u8]) -> Result<Self> {
        let mut bytes = BytesMut::from(val);

        let flag = bytes.get_u8();
        match flag {
            1u8 => Ok(Self::Ipv4(Ipv4Addr::from_bits(bytes.get_u32()))),
            2u8 => Ok(Self::Ipv6(Ipv6Addr::from_bits(bytes.get_u128()))),
            3u8 => {
                let lens = bytes.get_u8() as usize;
                assert!(bytes.len() >= lens);
                let domain_name = String::from_utf8_lossy(&bytes[..lens]);
                Ok(Self::DomainName(domain_name.to_string()))
            }
            _other => Err(anyhow!("unknown flag: {}", flag)),
        }
    }
}

impl Display for DstType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match &self {
            DstType::Ipv4(ipv4_addr) => write!(f, "ipv4:{ipv4_addr}"),
            DstType::Ipv6(ipv6_addr) => write!(f, "ipv6:{ipv6_addr}"),
            DstType::DomainName(name) => write!(f, "domain:{name}"),
        }
    }
}
impl ConnectRequest {
    #[allow(unused)]
    pub fn new(port: u16, t: DstType) -> Self {
        Self {
            dst_port: port,
            dst_type: t,
        }
    }
    pub fn as_bytes(&self) -> Vec<u8> {
        let total = self.dst_type.len() + 2;
        let mut v = Vec::with_capacity(total);
        // v.put_u8(total as u8);
        v.put_u16(self.dst_port);
        match &self.dst_type {
            DstType::Ipv4(ipv4_addr) => {
                v.push(1);
                v.extend_from_slice(ipv4_addr.octets().as_slice());
            }
            DstType::Ipv6(ipv6_addr) => {
                v.push(2);
                v.extend_from_slice(ipv6_addr.octets().as_slice());
            }
            DstType::DomainName(domain_name) => {
                v.push(3);
                v.push(domain_name.len() as u8);
                v.extend_from_slice(domain_name.as_bytes());
            }
        }
        v
    }
    pub fn dst_type(&self) -> &DstType {
        &self.dst_type
    }
    pub fn dst_as_atp(&self) -> SocksAddressType {
        match self.dst_type() {
            DstType::Ipv4(_) => SocksAddressType::Ipv4,
            DstType::Ipv6(_) => SocksAddressType::Ipv6,
            DstType::DomainName(_) => SocksAddressType::Domain,
        }
    }
    pub fn addr(&self) -> Vec<u8> {
        match self.dst_type() {
            DstType::Ipv4(ipv4_addr) => ipv4_addr.octets().to_vec(),
            DstType::Ipv6(ipv6_addr) => ipv6_addr.octets().to_vec(),
            DstType::DomainName(name) => name.as_bytes().to_vec(),
        }
    }
    pub fn port(&self) -> u16 {
        self.dst_port
    }
}
impl TryFrom<&[u8]> for ConnectRequest {
    type Error = anyhow::Error;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        let mut bytes = BytesMut::from(value);
        let port = bytes.get_u16();
        let remaining = &bytes[..];
        let dst = DstType::from_bytes(remaining)?;
        Ok(Self {
            dst_port: port,
            dst_type: dst,
        })
    }
}

impl TryFrom<(SocksAddressType, &[u8], u16)> for ConnectRequest {
    type Error = anyhow::Error;

    fn try_from(value: (SocksAddressType, &[u8], u16)) -> std::result::Result<Self, Self::Error> {
        let (arty, address, port) = value;
        match arty {
            SocksAddressType::Ipv4 => {
                let ipv4 = Ipv4Addr::new(address[0], address[1], address[2], address[3]);
                Ok(Self {
                    dst_port: port,
                    dst_type: DstType::Ipv4(ipv4),
                })
            }
            SocksAddressType::Domain => {
                let dn = String::from_utf8_lossy(address);
                Ok(Self {
                    dst_port: port,
                    dst_type: DstType::DomainName(dn.to_string()),
                })
            }
            SocksAddressType::Ipv6 => {
                let add: [u8; 16] = address.try_into().unwrap_or([0u8; 16]);
                let ipv6 = Ipv6Addr::from(add);
                Ok(Self {
                    dst_port: port,
                    dst_type: DstType::Ipv6(ipv6),
                })
            }
        }

        // todo!()
    }
}

impl Display for ConnectRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "addr {}, port {}", self.dst_type, self.dst_port)
    }
}

///连接结果
#[derive(Debug, PartialEq)]
pub(crate) struct EthanResponse {
    res: bool,
    reason: Option<String>,
}

impl EthanResponse {
    pub fn new(res: bool, reason: Option<String>) -> Self {
        Self { res, reason }
    }
    pub fn res(&self) -> bool {
        self.res
    }
    pub fn reason(&self) -> &Option<String> {
        &self.reason
    }

    pub fn as_bytes(&self) -> Vec<u8> {
        // let total = self.lens() + 1;
        let mut v = Vec::with_capacity(self.lens() + 1);
        // v.push(total as u8);
        match self.res {
            true => v.push(1),
            false => v.push(0),
        }
        match &self.reason {
            Some(s) => {
                v.push(s.len() as u8);
                v.extend_from_slice(s.as_bytes());
            }
            None => {
                v.push(0);
            }
        }
        v
    }
    pub fn into_response_bytes(self) -> Vec<u8> {
        let mut bytes = self.as_bytes();
        bytes.insert(0, bytes.len() as u8);
        bytes
    }

    fn lens(&self) -> usize {
        match &self.reason {
            Some(s) => s.len() + 2,
            None => 1,
        }
    }
}

impl TryFrom<&[u8]> for EthanResponse {
    type Error = anyhow::Error;

    fn try_from(value: &[u8]) -> std::result::Result<Self, Self::Error> {
        let mut bytes = BytesMut::from(value);
        let res = bytes.get_u8();
        let res = !res.eq(&0);
        let str_lens = bytes.get_u8();
        if str_lens > 0 {
            let _ = bytes.split_off(str_lens as usize);
            let str = String::from_utf8_lossy(&bytes);
            Ok(Self {
                res,
                reason: Some(str.to_string()),
            })
        } else {
            Ok(Self { res, reason: None })
        }
    }
}

#[derive(Debug, Clone)]
pub(crate) struct AuthRequest {
    uid: String,
    pwd: String,
}

impl AuthRequest {
    pub fn new(uid: String, pwd: String) -> Self {
        Self { uid, pwd }
    }
    pub fn into_bytes(self) -> Vec<u8> {
        let mut v = Vec::new();
        v.extend_from_slice(self.uid.as_bytes());
        v.extend_from_slice("💌".as_bytes());
        v.extend_from_slice(self.pwd.as_bytes());
        v
    }
    pub fn uid(&self) -> &str {
        &self.uid
    }
    pub fn pwd(&self) -> &str {
        &self.pwd
    }
}

impl TryFrom<&[u8]> for AuthRequest {
    type Error = ProxyError;

    fn try_from(value: &[u8]) -> std::result::Result<Self, Self::Error> {
        let str = String::from_utf8_lossy(value);
        if let Some((uid, pwd)) = str.split_once("💌") {
            Ok(Self {
                uid: uid.to_string(),
                pwd: pwd.to_string(),
            })
        } else {
            Err(ProxyError::EthanAuthRequestParseError)
        }
    }
}

#[cfg(test)]
mod test {
    use std::str::FromStr;

    use super::*;
    use anyhow::Result;

    #[test]
    fn auth_request_test() -> Result<()> {
        let request = AuthRequest::new("uid".into(), "pwd".into());
        let request_clone = request.clone();
        let bytes = request.into_bytes();
        let request2 = AuthRequest::try_from(bytes.as_slice())?;
        assert_eq!(request_clone.pwd, request2.pwd);
        assert_eq!(request_clone.uid, request2.uid);
        assert_eq!(request2.pwd, "pwd");
        assert_eq!(request2.uid, "uid");
        Ok(())
    }

    // #[test]
    // fn dsttype_test() -> Result<()> {
    //     let t1 = DstType::Ipv4(Ipv4Addr::new(192u8, 168, 100, 1));
    //     let t1_bytes = t1.into_bytes();
    //     let t1_recovered = DstType::from_bytes(t1_bytes.as_slice())?;
    //     assert_eq!(t1, t1_recovered);

    //     let t2 = DstType::DomainName("www.baidu.com".into());
    //     let t2_bytes = t2.into_bytes();
    //     let t2_recovered = DstType::from_bytes(&t2_bytes)?;
    //     assert_eq!(t2, t2_recovered);

    //     let ipv6 = Ipv6Addr::from_str("2001:0db8:85a3:0000:0000:8a2e:0370:7334")?;
    //     let t3 = DstType::Ipv6(ipv6);
    //     let t3_bytes = t3.into_bytes();
    //     let t3_recovered = DstType::from_bytes(&t3_bytes)?;
    //     assert_eq!(t3, t3_recovered);

    //     Ok(())
    // }

    #[test]
    fn connect_request_test() -> Result<()> {
        let domain_connect_request =
            ConnectRequest::new(9000, DstType::DomainName("www.baidu.com".into()));
        let cloned = domain_connect_request.clone();
        let tmp = domain_connect_request.as_bytes();
        let domain_connect_request2 = ConnectRequest::try_from(tmp.as_slice())?;
        assert_eq!(cloned, domain_connect_request2);

        let ipv4_connect_request =
            ConnectRequest::new(8000, DstType::Ipv4(Ipv4Addr::new(192u8, 168, 100, 1)));
        let cloned = ipv4_connect_request.clone();
        let tmp = ipv4_connect_request.as_bytes();
        let ipv4_connect_request2 = ConnectRequest::try_from(tmp.as_slice())?;
        assert_eq!(cloned, ipv4_connect_request2);

        let ipv6 = Ipv6Addr::from_str("2001:0db8:85a3:0000:0000:8a2e:0370:7334")?;
        let ipv6_connect_request = ConnectRequest::new(1000, DstType::Ipv6(ipv6));
        let cloned = ipv6_connect_request.clone();
        let tmp = ipv6_connect_request.as_bytes();
        let ipv6_connect_request2 = ConnectRequest::try_from(tmp.as_slice())?;
        assert_eq!(cloned, ipv6_connect_request2);

        Ok(())
    }

    #[test]
    fn response_rest() -> Result<()> {
        let response = EthanResponse::new(true, None);
        let bytes = response.as_bytes();
        let response2 = EthanResponse::try_from(bytes.as_slice())?;
        assert_eq!(response, response2);

        let false_response = EthanResponse::new(false, Some("failed message".into()));
        let bytes = false_response.as_bytes();
        let false_response2 = EthanResponse::try_from(bytes.as_slice())?;
        assert_eq!(false_response, false_response2);

        Ok(())
    }
}
