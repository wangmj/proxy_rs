use anyhow::{Result, anyhow};
use bytes::{Buf, BufMut, BytesMut};
use std::{
    mem,
    net::{Ipv4Addr, Ipv6Addr, SocketAddr},
};

use crate::socks5_proto::SocksAddressType;

///连接指令
#[derive(Debug, PartialEq)]
pub(crate) struct ConnectRequest {
    dst_port: u16,
    dst_type: DstType,
}

///目标地址类型
#[derive(Debug, PartialEq,Clone)]
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
    pub fn as_bytes(&self) -> Vec<u8> {
        let mut v = Vec::with_capacity(self.len());
        match self {
            DstType::Ipv4(ipv4_addr) => {
                v.put_u8(1);
                v.put_u32(ipv4_addr.to_bits());
                v
            }
            DstType::Ipv6(ipv6_addr) => {
                v.put_u8(2);
                v.put_u128(ipv6_addr.to_bits());
                v
            }
            DstType::DomainName(str) => {
                assert!(str.len() < u8::MAX as usize);

                v.put_u8(3);
                v.put_u8(str.len() as u8);
                v.put(str.as_bytes());
                v
            }
        }
    }

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

impl ConnectRequest {
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
        v.put(self.dst_type.as_bytes().as_slice());
        v
    }
    pub fn dst_type(&self) -> &DstType {
        &self.dst_type
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

    fn lens(&self) -> usize {
        match &self.reason {
            Some(s) => s.len() + 2,
            None => 0 + 1,
        }
    }
}

impl TryFrom<&[u8]> for EthanResponse {
    type Error = anyhow::Error;

    fn try_from(value: &[u8]) -> std::result::Result<Self, Self::Error> {
        let mut bytes = BytesMut::from(value);
        let res = bytes.get_u8();
        let res = if res.eq(&0) { false } else { true };
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

#[derive(Debug)]
pub(crate) struct AuthRequest {
    uid: String,
    pwd: String,
}

impl AuthRequest {
    pub fn new(uid: String, pwd: String) -> Self {
        Self { uid, pwd }
    }
    pub fn as_bytes(&self) -> Vec<u8> {
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
    type Error = anyhow::Error;

    fn try_from(value: &[u8]) -> std::result::Result<Self, Self::Error> {
        let str = String::from_utf8_lossy(value);
        if let Some((uid, pwd)) = str.split_once("💌") {
            Ok(Self {
                uid: uid.to_string(),
                pwd: pwd.to_string(),
            })
        } else {
            Err(anyhow!(
                "parse to auth request failed! not found split characters"
            ))
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
        let bytes = request.as_bytes();
        let request2 = AuthRequest::try_from(bytes.as_slice())?;
        assert_eq!(request.pwd, request2.pwd);
        assert_eq!(request.uid, request2.uid);
        assert_eq!(request2.pwd, "pwd");
        assert_eq!(request2.uid, "uid");
        Ok(())
    }

    #[test]
    fn dsttype_test() -> Result<()> {
        let t1 = DstType::Ipv4(Ipv4Addr::new(192u8, 168, 100, 1));
        let t1_bytes = t1.as_bytes();
        let t1_recovered = DstType::from_bytes(t1_bytes.as_slice())?;
        assert_eq!(t1, t1_recovered);

        let t2 = DstType::DomainName("www.baidu.com".into());
        let t2_bytes = t2.as_bytes();
        let t2_recovered = DstType::from_bytes(&t2_bytes)?;
        assert_eq!(t2, t2_recovered);

        let ipv6 = Ipv6Addr::from_str("2001:0db8:85a3:0000:0000:8a2e:0370:7334")?;
        let t3 = DstType::Ipv6(ipv6);
        let t3_bytes = t3.as_bytes();
        let t3_recovered = DstType::from_bytes(&t3_bytes)?;
        assert_eq!(t3, t3_recovered);

        Ok(())
    }

    #[test]
    fn connect_request_test() -> Result<()> {
        let domain_connect_request =
            ConnectRequest::new(9000, DstType::DomainName("www.baidu.com".into()));
        let tmp = domain_connect_request.as_bytes();
        let domain_connect_request2 = ConnectRequest::try_from(tmp.as_slice())?;
        assert_eq!(domain_connect_request, domain_connect_request2);

        let ipv4_connect_request =
            ConnectRequest::new(8000, DstType::Ipv4(Ipv4Addr::new(192u8, 168, 100, 1)));
        let tmp = ipv4_connect_request.as_bytes();
        let ipv4_connect_request2 = ConnectRequest::try_from(tmp.as_slice())?;
        assert_eq!(ipv4_connect_request, ipv4_connect_request2);

        let ipv6 = Ipv6Addr::from_str("2001:0db8:85a3:0000:0000:8a2e:0370:7334")?;
        let ipv6_connect_request = ConnectRequest::new(1000, DstType::Ipv6(ipv6));
        let tmp = ipv6_connect_request.as_bytes();
        let ipv6_connect_request2 = ConnectRequest::try_from(tmp.as_slice())?;
        assert_eq!(ipv6_connect_request, ipv6_connect_request2);

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
