use std::net::SocketAddr;
use std::str::FromStr;

use aleo_rust::{
    Address, AleoAPIClient, Block, Ciphertext, Credits, Network, Plaintext, PrivateKey,
    ProgramManager, Record, Testnet3, ViewKey,
};
use axum::{extract::State, http::StatusCode, routing::post, Json, Router};
use clap::Parser;
use db::{DBMap, RocksDB};
use serde::{Deserialize, Serialize};
use tokio::sync::mpsc::{self, Receiver, Sender};
use tower_http::cors::Any;
use tower_http::{cors::CorsLayer, trace, trace::TraceLayer};
use tracing::Level;

pub mod db;

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
        port,
    } = cli;

    let pk = PrivateKey::<Testnet3>::from_str(&pk).expect("private key");
    let vk = ViewKey::try_from(&pk).expect("view key");

    let faucet = AutoFaucet::new(aleo_rpc, pk, vk, from_height).expect("faucet");

    let addr = SocketAddr::from(([0,0,0,0], port));
    faucet.sync_and_initial(addr).await.expect("server panic");
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
        const BATCH_SIZE: usize = 45;

        for start in (cur..latest).step_by(BATCH_SIZE) {
            let end = (start + BATCH_SIZE as u32).min(latest);
            tracing::warn!("Fetched aleo blocks from {} to {}", start, end);
            self.client
                .get_blocks(start, end)?
                .into_iter()
                .for_each(|b| {
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
                if credits > 40000 {
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

    fn initial(self, rx: Receiver<Execution>) {
        let self_clone = self.clone();
        std::thread::spawn(move || loop {
            if let Err(e) = self_clone.sync() {
                tracing::error!("failed to sync aleo: {}", e);
            }
            tracing::info!("Holding records {:?}", self_clone.unspent_records.get_all());
            std::thread::sleep(std::time::Duration::from_secs(15));
        });
        std::thread::spawn(|| self.execute_program(rx));
    }

    pub async fn sync_and_initial(self, addr: SocketAddr) -> anyhow::Result<()> {
        self.sync().expect("failed to sync aleo");
        let (tx, rx) = mpsc::channel(1000);
        self.initial(rx);

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
            .with_state(tx)
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
}

async fn exec(
    State(tx): State<Sender<Execution>>,
    Json(req): Json<Execution>,
) -> anyhow::Result<Json<String>, (StatusCode, String)> {
    tx.send(req).await.map_err(|e| {
        tracing::error!("failed to send exec request: {:?}", e);
        (StatusCode::INTERNAL_SERVER_ERROR, e.to_string())
    })?;

    Ok(Json("already adding into execution queue".to_string()))
}
