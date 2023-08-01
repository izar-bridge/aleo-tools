use std::fs::File;
use std::io::{Read, Write};
use std::net::SocketAddr;
use std::path::Path;
use std::str::FromStr;

use aleo_rust::{
    Address, AleoAPIClient, Block, Ciphertext, Credits, Network, Plaintext, PrivateKey,
    ProgramManager, Record, Testnet3, ViewKey,
};
use axum::{extract::State, http::StatusCode, routing::post, Json, Router};
use clap::Parser;
use db::{DBMap, RocksDB};
use serde::{Deserialize, Serialize};
use tokio::sync::mpsc::Receiver;
use tower_http::cors::Any;
use tower_http::{cors::CorsLayer, trace, trace::TraceLayer};
use tracing::Level;

pub mod db;

const RESULT_PATH: &str = "result.txt";

#[derive(Debug, Parser)]
#[clap(name = "auto-faucet")]
pub struct Cli {
    #[clap(long)]
    pub aleo_rpc: Option<String>,

    #[clap(long)]
    pub pk: String,

    #[clap(long, default_value = "0")]
    pub from_height: u32,

    #[clap(long, default_value = "8989")]
    pub port: u16,

    #[clap(long)]
    pub path: Option<String>,

    #[clap(long, default_value = RESULT_PATH)]
    pub result_path: String,
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt().init();
    let cli = Cli::parse();
    tracing::info!("cli: {:?}", cli);
    let Cli {
        aleo_rpc,
        pk,
        from_height,
        path,
        result_path,
        port,
    } = cli;

    let pk = PrivateKey::<Testnet3>::from_str(&pk).expect("private key");
    let vk = ViewKey::try_from(&pk).expect("view key");

    let mut faucet = AutoFaucet::new(aleo_rpc, pk, vk, from_height).expect("faucet");
    faucet.sync().expect("failed to sync aleo");

    // TODO: add read script
    if let Some(path) = path {
        let mut result_file = File::options()
            .create(true)
            .append(true)
            .open(result_path.clone())
            .expect("result file");
        let execs = get_exec_from_path(path, result_path);
        for e in execs {
            for _ in 0..3 {
                match faucet.add_white_list(e.clone()) {
                    Ok((nft_id, tx_id)) => {
                        tracing::info!("Added nft: {:?} {:?}", nft_id, tx_id);
                        result_file
                            .write_all(format!("{} {}\n", nft_id, tx_id).as_bytes())
                            .expect("write result");
                        break;
                    }
                    Err(e) => {
                        tracing::error!("Error adding nft: {:?}", e);
                        tokio::time::sleep(std::time::Duration::from_secs(15)).await;
                    }
                }
            }

            if let Err(e) = faucet.sync() {
                tracing::error!("Error syncing: {:?}", e);
            }
        }
    }

    let addr = SocketAddr::from(([0, 0, 0, 0], port));
    faucet.sync_and_initial(addr).await.expect("server panic");
}

pub fn retry_with_times(
    times: usize,
    mut f: impl FnMut() -> anyhow::Result<()>,
) -> anyhow::Result<()> {
    for _ in 0..times {
        if let Ok(_) = f() {
            return Ok(());
        }
    }
    Err(anyhow::anyhow!("retry failed"))
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Execution {
    program_id: String,
    program_function: String,
    inputs: Vec<String>,
    fee: u64,
}

#[derive(Clone)]
pub struct AutoFaucet<N: Network> {
    pk: PrivateKey<N>,
    vk: ViewKey<N>,
    pm: ProgramManager<N>,
    client: AleoAPIClient<N>,
    agent: ureq::Agent,
    unspent_records: DBMap<String, Record<N, Plaintext<N>>>,
    network: DBMap<String, u32>,
    network_key: String,
}

impl<N: Network> AutoFaucet<N> {
    pub fn new(
        aleo_rpc: Option<String>,
        pk: PrivateKey<N>,
        vk: ViewKey<N>,
        from_height: u32,
    ) -> anyhow::Result<Self> {
        let unspent_records = RocksDB::open_map("unspent_records")?;
        let network = RocksDB::open_map("network")?;

        let (network_key, aleo_client) = match aleo_rpc {
            Some(aleo_rpc) => (
                format!("{}-{}", aleo_rpc, pk),
                AleoAPIClient::new(&aleo_rpc, "testnet3")?,
            ),
            None => (format!("aleo_main_net-{pk}"), AleoAPIClient::testnet3()),
        };

        let pm = ProgramManager::new(Some(pk), None, Some(aleo_client.clone()), None)?;
        let cur = network.get(&network_key)?.unwrap_or(0);
        if from_height > cur {
            network.insert(&network_key, &from_height)?;
        }

        Ok(Self {
            vk,
            pm,
            client: aleo_client,
            agent: ureq::Agent::new(),
            unspent_records,
            network,
            pk,
            network_key,
        })
    }

    pub fn sync(&self) -> anyhow::Result<()> {
        let cur = self.network.get(&self.network_key)?.unwrap_or(0);
        let latest = self.client.latest_height()?;
        tracing::debug!("Requesting aleo blocks from {} to {}", cur, latest);
        const BATCH_SIZE: usize = 50;

        for start in (cur..latest).step_by(BATCH_SIZE) {
            let end = (start + BATCH_SIZE as u32).min(latest);
            tracing::warn!("Fetched aleo blocks from {} to {}", start, end);
            self.get_blocks(start, end)?.into_iter().for_each(|b| {
                if let Err(e) = self.handle_credits(&b) {
                    tracing::error!("Error handling credits: {:?}", e);
                }
            })
        }

        self.network.insert(&self.network_key, &latest)?;
        tracing::info!("Synced aleo blocks from {} to {}", cur, latest);
        Ok(())
    }

    pub fn handle_credits(&self, block: &Block<N>) -> anyhow::Result<()> {
        // handle in
        block.clone().into_serial_numbers().for_each(|sn| {
            let _ = self.unspent_records.remove(&sn.to_string());
        });

        // handle out
        for (commit, record) in block.clone().into_records() {
            if !record.is_owner(&self.vk) {
                continue;
            }
            let sn = Record::<N, Ciphertext<N>>::serial_number(self.pk, commit)?;
            let record = record.decrypt(&self.vk)?;
            if let Ok(credits) = record.microcredits() {
                if credits > 4000000 {
                    tracing::info!("got a new record {:?}", record);
                    self.unspent_records.insert(&sn.to_string(), &record)?;
                }
            }
        }

        Ok(())
    }

    pub fn execute_program(mut self, mut rx: Receiver<Execution>) {
        while let Some(exec) = rx.blocking_recv() {
            let mut exec_f = |exec: Execution| {
                let (rid, fee_record) = self.get_record()?;
                let result = self.pm.execute_program(
                    exec.program_id,
                    exec.program_function,
                    exec.inputs.iter(),
                    exec.fee,
                    fee_record.clone(),
                    None,
                );

                if let Err(e) = &result {
                    if !e.to_string().contains("already exists in the ledger")
                        && !e.to_string().contains("Fee record does not have enough")
                    {
                        self.unspent_records.insert(&rid, &fee_record)?;
                    }
                }
                result
            };

            let result = exec_f(exec);
            tracing::info!("result: {:?}", result);
        }
    }

    pub fn get_blocks(&self, start_height: u32, end_height: u32) -> anyhow::Result<Vec<Block<N>>> {
        let start_time = std::time::Instant::now();
        let url = format!(
            "{}/{}/blocks?start={start_height}&end={end_height}",
            self.client.base_url(),
            self.client.network_id()
        );
        let blocks = match self.agent.get(&url).call()?.into_json() {
            Ok(blocks) => Ok(blocks),
            Err(error) => {
                anyhow::bail!("Failed to parse blocks {start_height} (inclusive) to {end_height} (exclusive): {error}")
            }
        };

        tracing::debug!(
            "Fetched aleo blocks from {} to {} in {:?}",
            start_height,
            end_height,
            start_time.elapsed()
        );
        blocks
    }

    fn initial(self) -> Self {
        let self_clone = self.clone();
        std::thread::spawn(move || loop {
            if let Err(e) = self_clone.sync() {
                tracing::error!("failed to sync aleo: {}", e);
            }
            tracing::info!("Holding records {:?}", self_clone.unspent_records.get_all());
            std::thread::sleep(std::time::Duration::from_secs(15));
        });
        self
    }

    pub async fn sync_and_initial(self, addr: SocketAddr) -> anyhow::Result<()> {
        self.sync().expect("failed to sync aleo");
        let node = self.initial();

        // initial server
        let cors = CorsLayer::new()
            .allow_origin(Any)
            .allow_methods([
                axum::http::Method::GET,
                axum::http::Method::POST,
                axum::http::Method::OPTIONS,
            ])
            .allow_headers([axum::http::header::CONTENT_TYPE]);
        let router = Router::new()
            .route("/exec", post(exec))
            .with_state(node)
            .layer(cors)
            .layer(
                TraceLayer::new_for_http()
                    .make_span_with(trace::DefaultMakeSpan::new().level(Level::INFO))
                    .on_response(trace::DefaultOnResponse::new().level(Level::INFO)),
            );

        tracing::info!("relayer listening on {}", addr);
        axum::Server::bind(&addr)
            .serve(router.into_make_service())
            .await?;
        Ok(())
    }

    pub fn get_record(&self) -> anyhow::Result<(String, Record<N, Plaintext<N>>)> {
        let record = self.unspent_records.pop_front()?;
        let (rid, record) = record.ok_or(anyhow::anyhow!("no fee record"))?;

        Ok((rid, record))
    }

    pub fn execute(&mut self, exec: Execution) -> anyhow::Result<String> {
        let (rid, fee_record) = self.get_record()?;
        let result = self.pm.execute_program(
            exec.program_id,
            exec.program_function,
            exec.inputs.iter(),
            exec.fee,
            fee_record.clone(),
            None,
        );

        if let Err(e) = &result {
            if !e.to_string().contains("already exists in the ledger")
                && !e.to_string().contains("Fee record does not have enough")
            {
                self.unspent_records.insert(&rid, &fee_record)?;
            }
        }
        result
    }

    pub fn transfer(&mut self, addr: Address<N>, amount: u64) -> anyhow::Result<(String, String)> {
        tracing::warn!("transfering to {} amount {amount}", addr);

        let records = self.unspent_records.pop_n_front(2)?;
        let (r1, transfer_record) = &records[0];
        let (r2, fee_record) = &records[1];
        let inputs = vec![
            transfer_record.to_string(),
            addr.to_string(),
            format!("{amount}u64"),
        ];

        match self.pm.execute_program(
            "credits.aleo",
            "transfer_private",
            inputs.iter(),
            25000,
            fee_record.clone(),
            None,
        ) {
            Ok(result) => Ok((addr.to_string(), result)),
            Err(e) => {
                if !e.to_string().contains("already exists in the ledger") {
                    tracing::warn!("reinsert unspent records");
                    self.unspent_records.insert(r1, transfer_record)?;
                    self.unspent_records.insert(r2, fee_record)?;
                }

                Err(e)
            }
        }
    }

    pub fn add_nft(&mut self, nft_id: String) -> anyhow::Result<(String, String)> {
        tracing::warn!("adding nft {nft_id}");

        let nft_input = from_nft_id(nft_id.clone());

        let (rid, fee_record) = self.get_record()?;

        let inputs = vec![nft_input, "0scalar".to_string()];

        let result = self.pm.execute_program(
            "izar_testnet3_nft_v1.aleo",
            "add_nft",
            inputs.iter(),
            40000,
            fee_record.clone(),
            None,
        );

        match result {
            Ok(result) => Ok((nft_id, result)),
            Err(e) => {
                if !e.to_string().contains("already exists in the ledger")
                    && (!e.to_string().contains("Fee record does not have enough")
                        && fee_record.microcredits().unwrap() < 40000)
                {
                    tracing::warn!("reinsert unspent records");
                    self.unspent_records.insert(&rid, &fee_record)?;
                }
                Err(e)
            }
        }
    }

    pub fn add_white_list(&mut self, addr: String) -> anyhow::Result<(String, String)> {
        tracing::warn!("adding white list {addr}");

        let (rid, fee_record) = self.get_record()?;

        let inputs = vec![addr.to_string(), "1u8".to_string()];

        let result = self.pm.execute_program(
            "izar_testnet3_nft_v1.aleo",
            "add_minter",
            inputs.iter(),
            40000,
            fee_record.clone(),
            None,
        );

        match result {
            Ok(result) => Ok((addr.to_string(), result)),
            Err(e) => {
                if !e.to_string().contains("already exists in the ledger")
                    && (!e.to_string().contains("Fee record does not have enough")
                        && fee_record.microcredits().unwrap() < 40000)
                {
                    tracing::warn!("reinsert unspent records");
                    self.unspent_records.insert(&rid, &fee_record)?;
                }
                Err(e)
            }
        }
    }
}

async fn exec<N: Network>(
    State(mut node): State<AutoFaucet<N>>,
    Json(req): Json<Execution>,
) -> anyhow::Result<Json<String>, (StatusCode, String)> {
    let tid = node.execute(req).map_err(|e| {
        tracing::error!("failed to execute: {}", e);
        (StatusCode::INTERNAL_SERVER_ERROR, e.to_string())
    })?;

    Ok(Json(tid))
}

pub fn from_nft_id(nft_id: String) -> String {
    let mut nft_bytes = [0u8; 32];
    nft_bytes[0..nft_id.len()].copy_from_slice(nft_id.as_bytes());

    let nft_1 = u128::from_le_bytes(nft_bytes[0..16].try_into().unwrap());
    let nft_2 = u128::from_le_bytes(nft_bytes[16..32].try_into().unwrap());

    format!("{{ data1:{nft_1}u128, data2:{nft_2}u128 }}")
}

pub fn get_exec_from_path(p: impl AsRef<Path>, filter_path: impl AsRef<Path>) -> Vec<String> {
    let mut file = std::fs::File::open(p).expect("file");

    let mut buf = String::new();
    file.read_to_string(&mut buf).expect("read");
    let mut vec = vec![];
    buf.lines().for_each(|e| {
        vec.push(e.to_string());
    });

    // filter addr
    {
        if let Ok(mut file) = std::fs::File::open(filter_path) {
            let mut buf = String::new();
            file.read_to_string(&mut buf).expect("read");
            vec.retain(|e| !buf.contains(e.to_string().as_str()));
        }
    }
    vec
}
