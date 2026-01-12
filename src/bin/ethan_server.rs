use proxy2_rs::ethan_server::EthanServer;

#[tokio::main]
async fn main() {
    env_logger::builder()
        .filter_level(log::LevelFilter::Trace)
        .init();
    let es = EthanServer::new(10800);
    es.start().await;
}
