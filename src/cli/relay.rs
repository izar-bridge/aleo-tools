use std::{net::SocketAddr, str::FromStr};

use aleo_rust::{PrivateKey, Testnet3};
use clap::Parser;

use crate::faucet::AutoFaucet;

#[derive(Debug, Parser)]
pub struct RelayCli {
    #[clap(long)]
    pub aleo_rpc: Option<String>,

    #[clap(long)]
    pub pk: String,

    #[clap(long)]
    pub from_height: Option<u32>,

    #[clap(long, default_value = "8989")]
    pub port: u16,
}

impl RelayCli {
    pub async fn parse(self) {
        let Self {
            aleo_rpc,
            pk,
            from_height,
            port,
        } = self;
        let pk = PrivateKey::<Testnet3>::from_str(&pk).expect("private key");

        let faucet = AutoFaucet::new(aleo_rpc, pk, from_height).expect("faucet");
        let addr = SocketAddr::from(([0, 0, 0, 0], port));

        if let Err(e) = faucet.sync_and_initial(addr).await {
            tracing::error!("server error: {e}");
        }
    }
}
