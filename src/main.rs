use clap::Parser;

pub mod cli;
pub mod db;
pub mod faucet;

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt().init();
    let cli = cli::Cli::parse();

    cli.command.parse().await;
}
