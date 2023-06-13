use std::{
    fs::File,
    io::{Read, Write},
    path::Path,
    str::FromStr, time::Duration,
};

use aleo_rust::{
    Address, AleoAPIClient, Block, Ciphertext, Credits, Network, Plaintext, PrivateKey,
    ProgramManager, Record, Testnet3, ViewKey,
};
use clap::Parser;
use db::{DBMap, RocksDB};

const RESULT_PATH: &str = "result.txt";

pub mod db;

#[derive(Debug, Parser)]
#[clap(name = "auto-faucet")]
pub struct Cli {
    #[clap(long)]
    pub aleo_rpc: Option<String>,

    #[clap(long)]
    pub path: String,

    #[clap(long)]
    pub pk: String,

    #[clap(long, default_value = "5000000")]
    pub amount: u64,

    #[clap(long, default_value = "0")]
    pub from_height: u32,
}

fn main() {
    tracing_subscriber::fmt().init();
    let cli = Cli::parse();
    tracing::info!("cli: {:?}", cli);
    let Cli {
        aleo_rpc,
        path,
        amount,
        pk,
        from_height,
    } = cli;

    let pk = PrivateKey::<Testnet3>::from_str(&pk).expect("private key");
    let vk = ViewKey::try_from(&pk).expect("view key");

    let faucet = AutoFaucet::new(aleo_rpc, pk, vk, from_height).expect("faucet");
    let addrs = get_addrs_from_path(path, RESULT_PATH);
    // open or create result file
    let mut result_file = File::options()
        .create(true)
        .append(true)
        .open(RESULT_PATH)
        .expect("result file");

    let (tx, rx) = std::sync::mpsc::channel();

    let mut faucet_clone = faucet.clone();
    std::thread::spawn(move || {
        for addr in addrs {
            if let Err(e) = faucet.sync() {
                tracing::error!("Error syncing: {:?}", e);
            }

            loop {
                if let Ok(lens) = faucet.unspent_records.lens() {
                    tracing::info!("unspent_records lens: {}", lens);
                    if lens >= 2 {
                        let record = faucet.unspent_records.pop_front().unwrap().unwrap();
                        let fee_record = faucet.unspent_records.pop_front().unwrap().unwrap();
                        tx.send((addr.clone(), record, fee_record)).unwrap();
                        break;
                    }
                }
                std::thread::sleep(Duration::from_secs(15));
                if let Err(e) = faucet.sync() {
                    tracing::error!("Error syncing: {:?}", e);
                }
            }
        }
    });

    while let Ok((addr, record, fee_record)) = rx.recv() {
        match faucet_clone.transfer(addr, amount, record.1.clone(), fee_record.1.clone()) {
            Ok((addr, tx_id)) => {
                tracing::info!("Transfered to {} tx_id {}", addr, tx_id);
                result_file
                    .write_all(format!("{} {}\n", addr, tx_id).as_bytes())
                    .expect("write result file");
            }
            Err(e) => {
                faucet_clone.unspent_records.insert(&record.0, &record.1).expect("insert record");
                faucet_clone
                    .unspent_records
                    .insert(&fee_record.0, &fee_record.1)
                    .expect("insert fee record");
                tracing::error!("Error transferring: {:?}", e);
            }
        }
    }
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

        let pm = ProgramManager::new(Some(pk.clone()), None, Some(aleo_client.clone()), None)?;
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

    pub fn transfer(
        &mut self,
        addr: Address<N>,
        amount: u64,
        record: Record<N, Plaintext<N>>,
        fee_record: Record<N, Plaintext<N>>,
    ) -> anyhow::Result<(String, String)> {
        tracing::warn!("transfering to {} amount {amount}", addr);

        let inputs = vec![record.to_string(), addr.to_string(), format!("{amount}u64")];

        let result = self.pm.execute_program(
            "credits.aleo",
            "transfer",
            inputs.iter(),
            25000,
            fee_record,
            None,
        )?;
        tracing::info!("transfer result: {:?}", result);
        Ok((addr.to_string(), result))
    }
}

pub fn get_addrs_from_path(
    p: impl AsRef<Path>,
    filter_path: impl AsRef<Path>,
) -> Vec<Address<Testnet3>> {
    let mut file = std::fs::File::open(p).expect("file");

    let mut buf = String::new();
    file.read_to_string(&mut buf).expect("read");
    let mut vec = vec![];
    buf.lines().for_each(|l| {
        if let Ok(addr) = Address::<Testnet3>::from_str(l) {
            vec.push(addr);
        } else {
            tracing::error!("invalid address: {}", l);
        }
    });
    // filter addr
    {
        if let Ok(mut file) = std::fs::File::open(filter_path) {
            let mut buf = String::new();
            file.read_to_string(&mut buf).expect("read");
            vec.retain(|addr| !buf.contains(addr.to_string().as_str()));
        }
    }
    vec
}
