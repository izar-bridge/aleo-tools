use std::{collections::HashMap, path::Path};

use aleo_rust::{
    Address, AleoAPIClient, Block, Ciphertext, Credits, Network, Plaintext, PrivateKey, Record,
};

use crate::{
    db::{DBMap, RocksDB},
    faucet::AleoExecutor,
};

#[derive(Clone)]
pub struct MultiClient<N: Network> {
    pub executors: HashMap<Address<N>, AleoExecutor<N>>,
    heights: DBMap<u16, u32>,
    records: DBMap<String, Record<N, Plaintext<N>>>,
}

impl<N: Network> MultiClient<N> {
    pub fn file(aleo_rpc: Option<String>, path: impl AsRef<Path>) -> anyhow::Result<Self> {
        let list = crate::cli::get_from_line::<PrivateKey<N>>(path)?;
        let executors = list
            .into_iter()
            .map(|pk| AleoExecutor::new(aleo_rpc.clone(), pk))
            .collect::<anyhow::Result<Vec<_>>>()?;
        let executors = executors
            .into_iter()
            .map(|e| (e.account(), e))
            .collect::<HashMap<_, _>>();
        let heights = RocksDB::open_map("heights")?;
        let records = RocksDB::open_map("records")?;
        Ok(MultiClient {
            executors,
            heights,
            records,
        })
    }

    pub fn client(&self) -> &AleoAPIClient<N> {
        self
            .executors
            .values()
            .next()
            .expect("no executor")
            .client()
    }

    pub fn records(&self) -> &DBMap<String, Record<N, Plaintext<N>>> {
        &self.records
    }

    pub fn sync(&self) -> anyhow::Result<()> {
        const BATCH_SIZE: usize = 50;
        let cur = self.get_local_height();
        let latest = self.client().latest_height()?;

        if cur >= latest {
            return Ok(());
        }

        for start in (cur..latest).step_by(BATCH_SIZE) {
            let end = (start + BATCH_SIZE as u32).min(latest);
            tracing::warn!("fetching aleo blocks from {} to {}", start, end);

            self.client()
                .get_blocks(start, end)?
                .into_iter()
                .for_each(|b| {
                    if let Err(e) = self.handle_block(b) {
                        tracing::error!("handle block error: {}", e);
                    }
                });

            self.heights.insert(&N::ID, &end)?;
        }

        Ok(())
    }

    pub fn get_local_height(&self) -> u32 {
        self.heights
            .get(&N::ID)
            .expect("height not found")
            .unwrap_or(0)
    }

    pub fn handle_block(&self, block: Block<N>) -> anyhow::Result<()> {
        // handle in
        block.clone().into_serial_numbers().for_each(|sn| {
            let _ = self.records.remove(&sn.to_string());
        });
        // handle out
        for (commit, record) in block.clone().into_records() {
            for e in self.executors.values() {
                if !record.is_owner(&e.view_key()) {
                    continue;
                }
                let sn = Record::<N, Ciphertext<N>>::serial_number(e.private_key(), commit)?;
                let record = record.decrypt(&e.view_key())?;
                if let Ok(credits) = record.microcredits() {
                    if credits >= 1000 {
                        tracing::info!("got a new record {:?}", record);
                        self.records.insert(&sn.to_string(), &record)?;
                    }
                }
            }
        }

        Ok(())
    }
}
