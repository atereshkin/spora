use std::collections::HashMap;
use std::sync::{Arc};
use tokio::io::{
    AsyncBufReadExt, AsyncWriteExt, BufReader, BufWriter, copy_bidirectional,
};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Mutex;
use clap::Parser;
use log::{error, info};

#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Args {
    // The hostname for "subscriber" connections
    #[arg(required = true)]
    pub_host: String,
    // Port to listen on for "subscribers"
    #[arg(short = 's', long, default_value_t = 2334)]
    sub_port: u16,
    // Port to listen on for "publishers"
    #[arg(short = 'p', long, default_value_t = 2335)]
    pub_port: u16
}

#[tokio::main]
async fn main() {
    env_logger::init();
    let args = Args::parse();
    let sub_listener = TcpListener::bind(("0.0.0.0", args.sub_port)).await.unwrap();
    let pub_listener = TcpListener::bind(("0.0.0.0", args.pub_port)).await.unwrap();
    let server = Arc::new(PubServer::new(args.pub_host, args.pub_port));
    {
        let server = server.clone();
        tokio::spawn(PubServer::listen_pub(server, pub_listener));
    }
    loop {
        let (socket, _) = sub_listener.accept().await.unwrap();
        let server = server.clone();
        tokio::spawn(async move {
             if let Err(e) = server.handle_sub(socket).await {
                 error!("Error while processing subscriber: {}", e);
            }
        });
    }
}

struct PubServer {
    pub_host: String,
    pub_port: u16,
    subscribers: Mutex<HashMap<String, TcpStream>>,
}

impl PubServer {
    fn new(pub_host: String, pub_port: u16) -> Self {
        PubServer {
            pub_host,
            pub_port,
            subscribers: Mutex::new(HashMap::new()),
        }
    }
    async fn handle_sub(&self, mut socket: TcpStream) -> std::io::Result<()> {
        let peer_addr = socket.peer_addr()?;
        let (reader, writer) = socket.split();
        let mut reader = BufReader::new(reader);
        let mut writer = BufWriter::new(writer);

        let mut key = String::new();
        reader.read_line(&mut key).await?;
        info!("SUB: {} {}", peer_addr, key);

        //TODO: we should check if subscriber is already there
        let mut subscribers = self.subscribers.lock().await;

        writer.write_all(format!("{}:{}\n", self.pub_host, self.pub_port).as_ref()).await?;
        writer.flush().await?;
        subscribers.insert(key, socket);
        Ok(())
    }

    async fn listen_pub(server: Arc<PubServer>, listener: TcpListener) {
        loop {
            let (socket, _) = listener.accept().await.unwrap();
            let server = server.clone();
            tokio::spawn(async move {
                if let Err(e) = server.handle_pub(socket).await {
                    error!("Error while handling publisher: {}", e);
                }
            });
        }
    }

    async fn handle_pub(&self, mut socket: TcpStream) -> std::io::Result<()> {
        let peer_addr = socket.peer_addr()?;
        let (reader, writer) = socket.split();
        let mut reader = BufReader::new(reader);
        let mut writer = BufWriter::new(writer);
        let mut key = String::new();
        reader.read_line(&mut key).await?;
        info!("PUB: {} {}", peer_addr, key);
        let mut subscriber: TcpStream;
        {
            let mut subscribers = self.subscribers.lock().await;
            if let Some(s) = subscribers.remove(&key) {
                subscriber = s;
            } else {
                info!("Unknown subscriber: {}", key);
                writer.write_all("ERROR: unknown subscriber\n".as_bytes()).await?;
                writer.flush().await?;
                return Ok(())
            }
        }
        writer.write_all("OK\n".as_bytes()).await?;
        writer.flush().await?;
        info!("Starting copy for {}", key);
        copy_bidirectional(&mut socket, &mut subscriber)
            .await?;
        Ok(())
    }
}
