use bytes::BufMut;
use anyhow::anyhow;

pub(crate) const SERVER_SUPPORTED_AUTHS: [AuthMethod; 2] = [AuthMethod::NoAuth, AuthMethod::UserPwd];
pub const SOCKS_VERSION: u8 = 0x05;

#[derive(Debug, PartialEq, Clone, Copy, PartialOrd, Eq, Ord)]
pub(crate) enum AuthMethod {
    NoAuth = 0x00,
    Gssapi = 0x01,
    UserPwd = 0x02,
    Reject = 0xFF,
}

impl From<u8> for AuthMethod {
    fn from(value: u8) -> Self {
        match value {
            0x00 => AuthMethod::NoAuth,
            0x01 => Self::Gssapi,
            0x02 => Self::UserPwd,
            0xFF => Self::Reject,
            _ => Self::Reject,
        }
    }
}
impl From<&u8> for AuthMethod{
    fn from(value: &u8) -> Self {
        AuthMethod::from(*value)
    }
}

impl From<AuthMethod> for u8 {
    fn from(value: AuthMethod) -> Self {
        match value {
            AuthMethod::NoAuth => 0x00,
            AuthMethod::Gssapi => 0x01,
            AuthMethod::UserPwd => 0x02,
            AuthMethod::Reject => 0xFF,
        }
    }
}

#[derive(Debug)]
pub(crate) enum Cmd {
    Connect,
    Bind,
    Udp,
}
impl TryFrom<u8> for Cmd {
    type Error = anyhow::Error;
    fn try_from(value: u8) -> std::result::Result<Self, Self::Error> {
        match value {
            0x01 => Ok(Self::Connect),
            0x02 => Ok(Self::Bind),
            0x03 => Ok(Self::Udp),
            _ => Err(anyhow!("unknown cmd")),
        }
    }
}

#[derive(Debug)]
pub(crate) struct SocksResponse {
    ver: u8,
    rep: SocksResponseType,
    rsv: u8, //保留字段
    atyp: SocksAddressType,
    dst_addr: Vec<u8>,
    dst_port: u16,
}
pub(crate) struct SocksResponseBuilder {
    rep: SocksResponseType,
    atyp: SocksAddressType,
    dst_addr: Vec<u8>,
    dst_port: u16,
}

impl SocksResponseBuilder {
    pub(crate) fn rep(&mut self, rep: SocksResponseType) -> &mut SocksResponseBuilder {
        self.rep = rep;
        self
    }
    pub(crate) fn atyp(&mut self, atyp: SocksAddressType) -> &mut SocksResponseBuilder {
        self.atyp = atyp;
        self
    }
    pub(crate) fn dst_addr(&mut self, addr: Vec<u8>) -> &mut SocksResponseBuilder {
        self.dst_addr = addr;
        self
    }
    pub(crate) fn dst_port(&mut self, port: u16) -> &mut SocksResponseBuilder {
        self.dst_port = port;
        self
    }
    pub(crate) fn build(self) -> SocksResponse {
        SocksResponse {
            ver: SOCKS_VERSION,
            rep: self.rep,
            rsv: 0x00,
            atyp: self.atyp,
            dst_addr: self.dst_addr,
            dst_port: self.dst_port,
        }
    }
}
#[allow(unused)]
impl SocksResponse {
    pub(crate) fn builder() -> SocksResponseBuilder {
        SocksResponseBuilder {
            rep: SocksResponseType::ServerError,
            atyp: SocksAddressType::Ipv4,
            dst_addr: vec![],
            dst_port: 0x00,
        }
    }
    pub(crate) fn rep(&self) -> SocksResponseType {
        self.rep
    }
    pub(crate) fn to_bytes(&self) -> Vec<u8> {
        let mut res = vec![];
        res.put_u8(self.ver);
        res.put_u8(self.rep.into());
        res.put_u8(self.rsv);
        res.put_u8(self.atyp.into());
        match self.atyp{
            SocksAddressType::Ipv4|SocksAddressType::Ipv6 =>  res.put(&self.dst_addr[..]),
            SocksAddressType::Domain => {
                res.put_u8(self.dst_addr.len() as u8);
                 res.put(&self.dst_addr[..]);
            },
            //SocksAddressType::Ipv6 => todo!(),
        }
        res.put_u16(self.dst_port);
        res
    }
}
/* REP是响应字段：
0x00：成功
0x01：服务器错误
0x02：规则禁止
0x03：网络不可达
0x04：主机不可达
0x05：连接被拒
0x06： TTL超时
0x07：不支持的命令
0x08：不支持的地址类型
0x09 - 0xFF：尚未定义 */
#[allow(dead_code)]
#[derive(Debug, Clone, Copy, PartialEq)]
pub(crate) enum SocksResponseType {
    Success,
    ServerError,
    RuleProhibits,
    NetWorkInAccessible,
    HostInAccessible,
    ConnectReject,
    TTLTimeout,
    NoSupportCommand,
    NoSupportAddressType,
    AddressIncorrect,
}

impl From<SocksResponseType> for u8 {
    fn from(value: SocksResponseType) -> Self {
        match value {
            SocksResponseType::Success => 0x00,
            SocksResponseType::ServerError => 0x01,
            SocksResponseType::RuleProhibits => 0x02,
            SocksResponseType::NetWorkInAccessible => 0x03,
            SocksResponseType::HostInAccessible => 0x04,
            SocksResponseType::ConnectReject => 0x05,
            SocksResponseType::TTLTimeout => 0x06,
            SocksResponseType::NoSupportCommand => 0x07,
            SocksResponseType::NoSupportAddressType => 0x08,
            SocksResponseType::AddressIncorrect => 0x09,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SocksAddressType {
    Ipv4,
    Domain,
    Ipv6,
}

impl From<SocksAddressType> for u8 {
    fn from(value: SocksAddressType) -> Self {
        match value {
            SocksAddressType::Ipv4 => 0x01,
            SocksAddressType::Domain => 0x03,
            SocksAddressType::Ipv6 => 0x04,
        }
    }
}