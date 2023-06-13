use std::{io::Read, path::Path, str::FromStr};

use aleo_rust::{
    Address, AleoAPIClient, Block, Ciphertext, Credits, Network, Plaintext, PrivateKey,
    ProgramManager, Record, Testnet3, ViewKey,
};
use clap::Parser;
use db::{DBMap, RocksDB};

pub mod db;

#[derive(Debug, Parser)]
#[clap(name = "auto-faucet")]
pub struct Cli {
    #[clap(long)]
    pub aleo_rpc: String,

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

    let mut faucet = AutoFaucet::new(aleo_rpc, pk, vk, from_height).expect("faucet");
    let addrs = get_addrs_from_path(path);

    for addr in addrs {
        if let Err(e) = faucet.sync() {
            tracing::error!("Error syncing: {:?}", e);
        }
        if let Err(e) = faucet.transfer(addr, amount) {
            tracing::error!("Error transferring: {:?}", e);
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
        aleo_rpc: String,
        pk: PrivateKey<N>,
        vk: ViewKey<N>,
        from_height: u32,
    ) -> anyhow::Result<Self> {
        let network_key = format!("{}-{}", aleo_rpc, pk);
        let unspent_records = RocksDB::open_map("unspent_records")?;
        let network = RocksDB::open_map("network")?;
        let cur = network.get(&network_key)?.unwrap_or(0);
        if from_height > cur {
            network.insert(&network_key, &from_height)?;
        }

        let aleo_client = AleoAPIClient::new(&aleo_rpc, "testnet3")?;
        let pm = ProgramManager::new(Some(pk.clone()), None, Some(aleo_client.clone()), None)?;

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

    pub fn transfer(&mut self, addr: Address<N>, amount: u64) -> anyhow::Result<(String, String)> {
        tracing::warn!("transfering to {} amount {amount}", addr);
        let (_, transfer_record) = self
            .unspent_records
            .pop_front()?
            .ok_or(anyhow::anyhow!("no unspent record for execution gas"))?;
        let (_, fee_record) = self
            .unspent_records
            .pop_front()?
            .ok_or(anyhow::anyhow!("no unspent record for execution gas"))?;
        let inputs = vec![
            transfer_record.to_string(),
            addr.to_string(),
            format!("{amount}u64"),
        ];

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

pub fn get_addrs_from_path(p: impl AsRef<Path>) -> Vec<Address<Testnet3>> {
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
    vec
}
