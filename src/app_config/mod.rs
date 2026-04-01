pub mod config;
mod inbound_config;
mod outbound_config;
pub use inbound_config::{EthanInBoundConfig,SocksInBoundConfig,InBoundTypeConfig,TlsServerConfig};
pub use outbound_config::{EthanOutBoundConfig,FreedomOutputConfig,OutputBoundTypeConfig,TlsClientConfig,DnsConfig,DNSResolver};
