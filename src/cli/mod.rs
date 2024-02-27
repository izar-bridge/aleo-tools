pub mod inscribe;
pub mod nft;
pub mod relay;

use std::{io::Read, path::Path, str::FromStr};

use clap::Parser;

use self::{inscribe::InscribeCli, nft::NftCli, relay::RelayCli};

#[derive(Debug, Parser)]
#[clap(name = "izar-tool")]
pub struct Cli {
    #[clap(subcommand)]
    pub command: Command,
}

#[derive(Debug, Parser)]
pub enum Command {
    #[clap(subcommand)]
    Nft(NftCli),
    #[clap(name = "relay")]
    Relay(RelayCli),
    #[clap(subcommand)]
    Inscribe(InscribeCli),
}

impl Command {
    pub async fn parse(self) {
        match self {
            Self::Relay(c) => c.parse().await,
            Self::Nft(c) => c.parse().await,
            Self::Inscribe(c) => c.parse().await,
        }
    }
}

pub fn get_from_line<T: FromStr>(path: impl AsRef<Path>) -> anyhow::Result<Vec<T>> {
    let mut file = std::fs::File::open(path)?;

    let mut buf = String::new();
    file.read_to_string(&mut buf)?;
    let mut list = vec![];

    buf.lines().for_each(|l| {
        if let Ok(t) = T::from_str(l) {
            list.push(t);
        }
    });

    Ok(list)
}
