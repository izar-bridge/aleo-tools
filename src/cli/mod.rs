pub mod multi;
pub mod nft;
pub mod relay;

use clap::Parser;

use self::{multi::MultiCli, nft::NftCli, relay::RelayCli};

#[derive(Debug, Parser)]
#[clap(name = "izar-tool")]
pub struct Cli {
    #[clap(subcommand)]
    pub command: Command,
}

#[derive(Debug, Parser)]
pub enum Command {
    #[clap(name = "multi")]
    Multi(MultiCli),
    #[clap(subcommand)]
    Nft(NftCli),
    #[clap(name = "relay")]
    Relay(RelayCli),
}

impl Command {
    pub async fn parse(self) {
        match self {
            Self::Multi(c) => c.parse(),
            Self::Relay(c) => c.parse().await,
            Self::Nft(c) => c.parse().await,
        }
    }
}
