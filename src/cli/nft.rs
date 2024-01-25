use std::{io::Write, path::PathBuf, str::FromStr, time::Duration};

use aleo_rust::{Address, PrivateKey, Testnet3};
use clap::Parser;

use crate::faucet::AleoExecutor;

use super::get_from_line;

#[derive(Debug, Parser)]
pub enum NftCli {
    Nft {
        #[clap(long)]
        aleo_rpc: Option<String>,

        #[clap(long)]
        pk: String,

        #[clap(long)]
        path: PathBuf,

        #[clap(long, default_value = "result.txt")]
        output: PathBuf,
    },

    WhiteList {
        #[clap(long)]
        aleo_rpc: Option<String>,

        #[clap(long)]
        pk: String,

        #[clap(long)]
        path: PathBuf,

        #[clap(long, default_value = "result.txt")]
        output: PathBuf,
    },
}

impl NftCli {
    pub async fn parse(self) {
        match self {
            Self::Nft {
                aleo_rpc,
                pk,
                path,
                output,
            } => {
                let pk = PrivateKey::<Testnet3>::from_str(&pk).expect("private key error: {e}");
                let mut output_file = std::fs::File::options()
                    .create(true)
                    .append(true)
                    .open(output.clone())
                    .expect("result file");
                let mut faucet =
                    AleoExecutor::new(aleo_rpc, pk).expect("execution node error: {e}");
                let nfts = get_from_line::<NFTStr>(path).expect("get nfts from path error: {e}");

                for nft in nfts {
                    for _ in 0..3 {
                        match faucet.add_nft(nft.to_string()) {
                            Ok((nft_id, tx_id)) => {
                                tracing::info!("Added nft: {:?} {:?}", nft_id, tx_id);
                                output_file
                                    .write_all(format!("{} {}\n", nft_id, tx_id).as_bytes())
                                    .expect("write result");
                                break;
                            }
                            Err(e) => tracing::error!("Error adding nft: {:?}", e),
                        }
                    }
                    tokio::time::sleep(Duration::from_secs(10)).await;
                }
            }
            Self::WhiteList {
                aleo_rpc,
                pk,
                path,
                output,
            } => {
                let pk = PrivateKey::<Testnet3>::from_str(&pk).expect("private key error: {e}");
                let mut output_file = std::fs::File::options()
                    .create(true)
                    .append(true)
                    .open(output.clone())
                    .expect("result file");
                let mut faucet =
                    AleoExecutor::new(aleo_rpc, pk).expect("execution node error: {e}");
                let addrs = get_from_line::<Address<Testnet3>>(path)
                    .expect("get nfts from path error: {e}");

                for addr in addrs {
                    for _ in 0..3 {
                        match faucet.add_white_list(addr.to_string()) {
                            Ok((addr, tx_id)) => {
                                tracing::info!("Added whitelist: {:?} {:?}", addr, tx_id);
                                output_file
                                    .write_all(format!("{} {}\n", addr, tx_id).as_bytes())
                                    .expect("write result");
                                break;
                            }
                            Err(e) => tracing::error!("Error adding whitelist: {:?}", e),
                        }
                    }
                    tokio::time::sleep(Duration::from_secs(10)).await;
                }
            }
        }
    }
}

pub struct NFTStr {
    inner: String,
}

impl ToString for NFTStr {
    fn to_string(&self) -> String {
        self.inner.clone()
    }
}

impl FromStr for NFTStr {
    type Err = anyhow::Error;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut nft_bytes = [0u8; 32];
        nft_bytes[0..s.len()].copy_from_slice(s.as_bytes());

        let nft_1 = u128::from_le_bytes(nft_bytes[0..16].try_into()?);
        let nft_2 = u128::from_le_bytes(nft_bytes[16..32].try_into()?);

        let inner = format!("{{ data1:{nft_1}u128, data2:{nft_2}u128 }}");

        Ok(NFTStr { inner })
    }
}
