use std::{io::Write, path::PathBuf, str::FromStr};

use aleo_rust::{Address, PrivateKey, Testnet3};
use clap::Parser;
use rand::Rng;
use serde::{Deserialize, Serialize};
use snarkvm::console::program::Owner;

use crate::faucet::{AleoExecutor, Execution};

use super::get_from_line;

#[derive(Debug, Parser)]
pub enum InscribeCli {
    Inscribe {
        #[clap(long)]
        aleo_rpc: Option<String>,

        #[clap(long)]
        path: PathBuf,

        #[clap(long)]
        number: u64,

        #[clap(long, default_value = "inscribe_result.txt")]
        output: PathBuf,
    },

    Gas {
        #[clap(long)]
        aleo_rpc: Option<String>,

        #[clap(long)]
        pk: String,

        #[clap(long)]
        path: PathBuf,

        #[clap(long)]
        amount: u64,

        #[clap(long, default_value = "gas_result.txt")]
        output: PathBuf,
    },

    GenAccount {
        #[clap(long)]
        number: u64,

        #[clap(long, default_value = "accounts.txt")]
        output: PathBuf,
    },
}

impl InscribeCli {
    pub async fn parse(self) {
        match self {
            Self::Gas {
                aleo_rpc,
                amount,
                pk,
                path,
                output,
            } => {
                let pk = PrivateKey::<Testnet3>::from_str(&pk).expect("private key error");
                let addrs = get_from_line::<Address<Testnet3>>(path)
                    .expect("get addresses from path error");
                let mut output_file = std::fs::File::create(output.clone()).expect("result file");

                let mut faucet = AleoExecutor::new(aleo_rpc, pk).expect("execution node error");

                for addr in addrs {
                    let transfer_public = Execution {
                        program_id: "credits.aleo".to_string(),
                        program_function: "transfer_public".to_string(),
                        inputs: vec![addr.to_string(), format!("{}u64", amount)],
                        fee: 5000,
                    };
                    match faucet.execute(transfer_public) {
                        Ok(tid) => writeln!(output_file, "{tid}, {addr}").expect("write success"),
                        Err(e) => {
                            writeln!(output_file, "error: {}: {}", addr, e).expect("write error")
                        }
                    }

                    let transfer_private = Execution {
                        program_id: "credits.aleo".to_string(),
                        program_function: "transfer_public_to_private".to_string(),
                        inputs: vec![addr.to_string(), format!("5000u64")],
                        fee: 5000,
                    };

                    match faucet.execute(transfer_private) {
                        Ok(tid) => {
                            writeln!(output_file, "{tid}, {addr}").expect("write success");
                        }
                        Err(e) => {
                            writeln!(output_file, "error: {}: {}", addr, e).expect("write error");
                        }
                    }
                }
            }

            Self::GenAccount { number, output } => {
                let mut output_file = std::fs::File::create(output.clone()).expect("result file");
                let mut rng = rand::thread_rng();
                for _ in 0..number {
                    let pk = PrivateKey::<Testnet3>::new(&mut rng).unwrap();
                    writeln!(output_file, "{}", pk).expect("write success");
                }
            }

            Self::Inscribe {
                aleo_rpc,
                path,
                mut number,
                output,
            } => {
                let mut multi = crate::multi::MultiClient::<Testnet3>::file(aleo_rpc, path)
                    .expect("multi client error");
                let mut output_file = std::fs::File::create(output.clone()).expect("result file");
                let mut rng = rand::thread_rng();
                loop {
                    if let Err(e) = multi.sync() {
                        tracing::error!("sync error: {}", e);
                    }

                    let records = multi.records().get_all().unwrap();
                    for (rid, r) in records {
                        if let Owner::Public(who) = r.owner() {
                            let executor = multi.executors.get_mut(&who).unwrap();
                            let inscribe = Execution {
                                program_id: "unizexe_protocol.aleo".to_string(),
                                program_function: "inscribe".to_string(),
                                inputs: vec![get_random_inscription(&mut rng), r.to_string()],
                                fee: 5000,
                            };
                            match executor.execute(inscribe) {
                                Ok(tid) => {
                                    multi.records().remove(&rid).unwrap();
                                    number -= 1;
                                    tracing::info!("inscribe success: {}", tid);
                                    writeln!(output_file, "{who},{tid}").unwrap();
                                    if number == 0 {
                                        return;
                                    }
                                }
                                Err(e) => {
                                    tracing::error!("inscribe error: {}", e);
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}

fn get_random_inscription<R: Rng>(rng: &mut R) -> String {
    let url = "https://bullscriptions.com/api/v1/iarc-20?page=0&page_size=200";
    let resp = ureq::get(url).call().unwrap().into_string().unwrap();
    let json: serde_json::Value = serde_json::from_str(&resp).unwrap();
    let list = json["data"]["list"].as_array().unwrap();

    let idx = rng.gen_range(0..list.len());
    let tick = list[idx]["tick"].as_str().unwrap();
    let lim = list[idx]["lim"].as_u64().unwrap();
    println!("{}: {}", tick, lim);
    let mut json_str = serde_json::json!(
        {
            "p": "iarc-20",
            "op": "mint",
            "tick": format!("{tick}"),
            "amt": lim,
        }
    )
    .to_string().as_bytes().to_vec();
    json_str.resize(32 * 16 * 16, 0);
    let raw = InscriptionRawData::from_slice(&json_str).unwrap();

    raw.to_string()
}

#[test]
fn test_get_random_inscription() {
    let mut rng = rand::thread_rng();
    for i in 0..10 {
        let ins = get_random_inscription(&mut rng);
    }
}

#[derive(Copy, Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct InscriptionRawData([[u128; 16]; 32]);

impl InscriptionRawData {
    pub fn to_vec(&self) -> Vec<u8> {
        let mut vec = Vec::new();
        for i in 0..32 {
            for j in 0..16 {
                vec.extend_from_slice(&self.0[i][j].to_le_bytes());
            }
        }
        vec
    }

    pub fn from_slice(vec: &[u8]) -> anyhow::Result<Self> {
        if vec.len() != 32 * 16 * 16 {
            anyhow::bail!("Invalid slice length")
        }
        let mut arr = [[0u128; 16]; 32];
        for i in 0..32 {
            for j in 0..16 {
                let mut bytes = [0u8; 16];
                bytes.copy_from_slice(&vec[(i * 16 + j) * 16..(i * 16 + j + 1) * 16]);
                arr[i][j] = u128::from_le_bytes(bytes);
            }
        }
        Ok(Self(arr))
    }

    pub const fn size() -> usize {
        32 * 16 * 16
    }
}

impl ToString for InscriptionRawData {
    fn to_string(&self) -> String {
        let mut raw_str = "[".to_string();
        for i in 0..32 {
            raw_str.push('[');
            for j in 0..16 {
                raw_str.push_str(&format!("{}u128", self.0[i][j]));
                if j != 15 {
                    raw_str.push(',');
                }
            }
            raw_str.push(']');
            if i != 31 {
                raw_str.push(',');
            }
        }
        raw_str.push(']');
        raw_str
    }
}
