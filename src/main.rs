use proxy2_rs::socks5::Socks5Services;

#[tokio::main]
async fn main() {
    env_logger::builder()
        .filter_level(log::LevelFilter::Trace)
        .init();

    let socks = Socks5Services::new().await;
    let rt = match tokio::runtime::Runtime::new() {
        Ok(rt) => rt,
        Err(e) => {
            eprintln!("start tokio runtime failed, {}", e);
            return;
        }
    };
    rt.block_on(async move {
        // socks.clean().await;
        match socks.start().await {
            Ok(_) => {
                println!("start success!")
            }
            Err(e) => {
                eprintln!("failed to start socks5, {}", e);
            }
        }
    });
}
