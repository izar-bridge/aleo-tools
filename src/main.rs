use clap::Parser;

pub mod cli;
pub mod db;
pub mod faucet;
pub mod multi;

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt().init();
    let cli = cli::Cli::parse();

    cli.command.parse();
}

// const RESULT_PATH: &str = "result.txt";
// #[derive(Debug, Parser)]
// #[clap(name = "auto-faucet")]
// pub struct Cli {
//     #[clap(long)]
//     pub aleo_rpc: Option<String>,

//     #[clap(long)]
//     pub pk: String,

//     #[clap(long, default_value = "0")]
//     pub from_height: u32,

//     #[clap(long, default_value = "8989")]
//     pub port: u16,

//     #[clap(long)]
//     pub path: Option<String>,

//     #[clap(long, default_value = RESULT_PATH)]
//     pub result_path: String,
// }

// #[tokio::main]
// async fn main() {
//     tracing_subscriber::fmt().init();
//     let cli = Cli::parse();
//     tracing::info!("cli: {:?}", cli);
//     let Cli {
//         aleo_rpc,
//         pk,
//         from_height,
//         path,
//         result_path,
//         port,
//     } = cli;

//     let pk = PrivateKey::<Testnet3>::from_str(&pk).expect("private key");
//     let vk = ViewKey::try_from(&pk).expect("view key");

//     let mut faucet = AutoFaucet::new(aleo_rpc, pk, vk, from_height).expect("faucet");
//     faucet.sync().expect("failed to sync aleo");

//     // TODO: add read script
//     if let Some(path) = path {
//         let mut result_file = File::options()
//             .create(true)
//             .append(true)
//             .open(result_path.clone())
//             .expect("result file");
//         let execs = get_exec_from_path(path, result_path);
//         for e in execs {
//             for _ in 0..3 {
//                 match faucet.transfer(e.clone(), 1000000000000) {
//                     Ok((nft_id, tx_id)) => {
//                         tracing::info!("Added nft: {:?} {:?}", nft_id, tx_id);
//                         result_file
//                             .write_all(format!("{} {}\n", nft_id, tx_id).as_bytes())
//                             .expect("write result");
//                         break;
//                     }
//                     Err(e) => {
//                         tracing::error!("Error adding nft: {:?}", e);
//                         tokio::time::sleep(std::time::Duration::from_secs(15)).await;
//                     }
//                 }
//             }

//             if let Err(e) = faucet.sync() {
//                 tracing::error!("Error syncing: {:?}", e);
//             }
//         }
//     }

//     let addr = SocketAddr::from(([0, 0, 0, 0], port));
//     faucet.sync_and_initial(addr).await.expect("server panic");
// }
