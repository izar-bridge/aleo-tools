use std::{net::SocketAddr, str::FromStr};

use aleo_rust::{PrivateKey, Testnet3};
use clap::Parser;

use crate::faucet::AleoExecutor;

#[derive(Debug, Parser)]
pub struct RelayCli {
    #[clap(long)]
    pub aleo_rpc: Option<String>,

    #[clap(long)]
    pub pk: String,

    #[clap(long, default_value = "8989")]
    pub port: u16,
}

impl RelayCli {
    pub async fn parse(self) {
        let Self {
            aleo_rpc,
            pk,
            port,
        } = self;
        let pk = PrivateKey::<Testnet3>::from_str(&pk).expect("private key");

        let faucet = AleoExecutor::new(aleo_rpc, pk).expect("faucet");
        let addr = SocketAddr::from(([0, 0, 0, 0], port));

        if let Err(e) = faucet.initial(addr).await {
            tracing::error!("server error: {e}");
        }
    }
}
