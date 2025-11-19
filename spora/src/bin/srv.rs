use std::time::Duration;
use tokio::time::sleep;
use ux::share;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // ux::start().await;
    let ep = share().await?;
    println!("Accepting packets at {}:{}", ep.hostname, ep.port);
    sleep(Duration::from_secs(1000)).await;
    Ok(())
}