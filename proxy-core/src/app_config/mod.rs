pub mod config;
mod inbound_config;
mod outbound_config;
pub mod dns_config;
pub mod route_config;
pub mod log_config;
pub use inbound_config::{EthanInBoundConfig,SocksInBoundConfig,InBoundTypeConfig,TlsServerConfig};
pub use outbound_config::{EthanOutBoundConfig,DirectOutputConfig,OutBoundTypeConfig};
