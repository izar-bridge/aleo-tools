use std::io::Read;
use std::net::SocketAddr;
use std::path::Path;
use std::str::FromStr;

use crate::db::{DBMap, RocksDB};
use aleo_rust::{
    Address, AleoAPIClient, Block, Ciphertext, Credits, Network, Plaintext, PrivateKey,
    ProgramManager, Record, ViewKey,
};
use axum::{extract::State, http::StatusCode, routing::post, Json, Router};
use serde::{Deserialize, Serialize};
use tokio::sync::mpsc::Receiver;
use tower_http::cors::Any;
use tower_http::{cors::CorsLayer, trace, trace::TraceLayer};
use tracing::Level;

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
            tracing::info!("Holding records balance {:?}", self_clone.get_balance());
            std::thread::sleep(std::time::Duration::from_secs(15));
        });
        self
    }

    pub fn get_balance(&self) -> anyhow::Result<u64> {
        let mut balance = 0;
        for (_, record) in self.unspent_records.get_all()? {
            balance += record.microcredits()?;
        }
        Ok(balance)
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

    pub fn transfer(&mut self, addr: String, amount: u64) -> anyhow::Result<(String, String)> {
        let addr: Address<N> = Address::<N>::from_str(&addr)?;
        tracing::warn!("transfering to {} amount {amount}", addr);

        let records = self.unspent_records.pop_n_front(2)?;
        let (r1, transfer_record) = &records[0];
        let (r2, fee_record) = &records[1];

        match self.pm.transfer(
            amount,
            25000,
            addr,
            aleo_rust::TransferType::Private,
            None,
            Some(transfer_record.clone()),
            fee_record.clone(),
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

#[test]
fn test_gen_token_id() {
    let token_name = "arbitrum".to_string();

    let mut name_bytes = token_name.as_bytes().to_vec();

    name_bytes.resize(16, 0);

    let buf: [u8; 16] = name_bytes.try_into().unwrap();

    let name_u128 = u128::from_le_bytes(buf);

    println!("{name_u128}");

    let name_bytes = name_u128.to_le_bytes().to_vec();
    let name = String::from_utf8(name_bytes).unwrap();

    println!("{name}");
}

#[test]
fn test_gen_addr() {
    use aleo_rust::Testnet3;
    use std::fs::File;
    use std::io::Write;

    let mut rng = rand::thread_rng();
    let mut file = File::options()
        .create(true)
        .append(true)
        .open("address.txt")
        .expect("result file");
    for _ in 0..2000 {
        let private_key = PrivateKey::<Testnet3>::new(&mut rng).unwrap();
        let expected = Address::try_from(private_key).unwrap().to_string();
        let line = format!("{expected}\n");

        file.write_all(line.as_bytes()).unwrap();
    }
}
