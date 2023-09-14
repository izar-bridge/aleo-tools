use std::{ops::Index, str::FromStr, time::Duration};

use aleo_rust::{
    Address, AleoAPIClient, Block, Ciphertext, Credits, Network, Plaintext, PrivateKey,
    ProgramManager, Record, ViewKey, ConsensusStore, ConsensusMemory, VM, Query,
};
use rand::Rng;
use rayon::prelude::*;

use crate::db::{DBMap, RocksDB};

const CREDITS_PROGRAM: &str = "credits.aleo";

pub struct MultiManager<N: Network> {
    pm: ProgramManager<N>,
    multi: Vec<ManagerUnit<N>>,
    client: AleoAPIClient<N>,
    current_height: DBMap<u32, u32>,
    receivers: Vec<Address<N>>,
}
pub struct ManagerUnit<N: Network> {
    pub pk: PrivateKey<N>,
    pub vk: ViewKey<N>,
    pub addr: Address<N>,
    pub records: DBMap<String, Record<N, Plaintext<N>>>,
    pub balance: u64,
}

impl<N: Network> ManagerUnit<N> {
    pub fn new(pk: PrivateKey<N>) -> anyhow::Result<Self> {
        let vk = ViewKey::try_from(&pk)?;
        let addr = Address::try_from(&vk)?;
        let records_prf = format!("{}-unspent_records", addr);
        let records = RocksDB::open_map(&records_prf)?;

        Ok(Self {
            pk,
            vk,
            addr,
            records,
            balance: 0,
        })
    }
}

impl<N: Network> MultiManager<N> {
    pub fn new(
        aleo_rpc: Option<String>,
        pks: Vec<PrivateKey<N>>,
        receivers: Vec<Address<N>>,
        from_height: Option<u32>,
    ) -> anyhow::Result<Self> {
        let current_height = RocksDB::open_map::<u32, u32>("current_height")?;
        if let Some(height) = from_height {
            current_height.insert(&1, &height)?;
        }

        let aleo_client = match aleo_rpc {
            Some(aleo_rpc) => AleoAPIClient::new(&aleo_rpc, "testnet3")?,
            None => AleoAPIClient::testnet3(),
        };

        let pm = ProgramManager::new(Some(pks[0].clone()), None, Some(aleo_client.clone()), None)?;
        let mut multi = vec![];
        for pk in pks {
            match ManagerUnit::new(pk) {
                Ok(u) => multi.push(u),
                Err(e) => tracing::info!("cant new unit {pk}: {e}"),
            }
        }

        Ok(Self {
            pm,
            multi,
            receivers,
            client: aleo_client,
            current_height,
        })
    }

    pub fn sync(&self) -> anyhow::Result<()> {
        let cur = self.current_height.get(&1)?.unwrap_or(0);
        let latest = self.client.latest_height()?;
        tracing::debug!("Requesting aleo blocks from {} to {}", cur, latest);
        const BATCH_SIZE: usize = 50;

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

        self.current_height.insert(&1, &latest)?;
        tracing::info!("Synced aleo blocks from {} to {}", cur, latest);
        Ok(())
    }

    pub fn fast_sync(&self) -> anyhow::Result<()> {
        let cur = self.current_height.get(&1)?.unwrap_or(0);
        let latest = self.client.latest_height()?;
        tracing::info!("sync aleo from {} to {}", cur, latest);

        if cur >= latest {
            return Ok(());
        }

        const BATCH_SIZE: usize = 500;

        for start in (cur..latest).step_by(BATCH_SIZE) {
            let end = (start + BATCH_SIZE as u32).min(latest);

            self.fast_get_blocks(start, end)?.into_iter().for_each(|b| {
                if let Err(e) = self.handle_credits(&b) {
                    tracing::error!("handle credits error: {:?}", e);
                }
            });
        }

        self.current_height.insert(&1, &latest)?;

        Ok(())
    }

    fn fast_get_blocks(&self, st: u32, ed: u32) -> anyhow::Result<Vec<Block<N>>> {
        const BATCH_SIZE: usize = 500;

        if ed - st > BATCH_SIZE as u32 {
            return Err(anyhow::anyhow!("too large batch size"));
        }

        let par_getter = (st..ed)
            .step_by(50)
            .map(|st| (st, (st + 50).min(ed)))
            .collect::<Vec<(u32, u32)>>();

        let blocks = par_getter
            .par_iter()
            .map(|(st, ed)| {
                tracing::warn!("fetching aleo blocks from {} to {}", st, ed);
                self.client.get_blocks(*st, *ed)
            })
            .collect::<anyhow::Result<Vec<Vec<Block<N>>>>>()?
            .into_iter()
            .flatten()
            .collect::<Vec<Block<N>>>();

        Ok(blocks)
    }

    pub fn handle_credits(&self, block: &Block<N>) -> anyhow::Result<()> {
        // handle in
        block.clone().into_serial_numbers().for_each(|sn| {
            self.multi.iter().for_each(|u| {
                let _ = u.records.remove(&sn.to_string());
            });
        });

        // handle out
        for (commit, record) in block.clone().into_records() {
            for u in self.multi.iter() {
                if !record.is_owner(&u.vk) {
                    continue;
                }
                let sn = Record::<N, Ciphertext<N>>::serial_number(u.pk, commit)?;
                let record = record.decrypt(&u.vk)?;
                if let Ok(credits) = record.microcredits() {
                    if credits > 4000000 {
                        tracing::info!("got a new record {:?}", record);
                        u.records.insert(&sn.to_string(), &record)?;
                        break;
                    }
                }
            }
        }
        Ok(())
    }

    pub fn gen_transfer_executions(&self) -> Vec<TransferExecution<N>> {
        let mut executions = vec![];
        for (idx, u) in self.multi.iter().enumerate() {
            while let Ok(r) = u.records.pop_n_front(2) {
                let amount_record = r[0].clone();
                if let Ok(amount) = amount_record.1.microcredits() {
                    let execution = TransferExecution {
                        multi_idx: idx,
                        receiver: self.select_receiver(),
                        amount,
                        amount_record,
                        fee_record: r[1].clone(),
                    };
                    executions.push(execution);
                }
            }
        }

        executions
    }

    pub fn handle_execution(&self, execution: TransferExecution<N>) -> anyhow::Result<String> {
        let query = Query::from(self.pm.api_client().as_ref().unwrap().base_url());

        let TransferExecution {
            multi_idx,
            receiver,
            amount_record,
            fee_record,
            amount,
        } = execution;
        let (_, amount_record) = amount_record;
        let (_, fee_record) = fee_record;

        let (function_id, inputs) = (
            "transfer_private",
            vec![
                snarkvm::console::program::Value::Record(amount_record.clone()),
                snarkvm::console::program::Value::from_str(&receiver.to_string())?,
                snarkvm::console::program::Value::from_str(&format!("{}u64", amount))?,
            ],
        );

        let pk = &self.multi.index(multi_idx).pk;


        // Initialize a VM
        let rng = &mut rand::thread_rng();
        let store = ConsensusStore::<N, ConsensusMemory<N>>::open(None)?;
        let vm = VM::from(store)?;

        let transaction = vm.execute(
            pk,
            (CREDITS_PROGRAM, function_id),
            inputs.iter(),
            Some((fee_record, 5000)),
            Some(query),
            rng,
        )?;

        // Broadcast the execution transaction to the network
        tracing::warn!("Attempting to broadcast execution transaction for {CREDITS_PROGRAM}");
        self.pm.broadcast_transaction(transaction)
    }

    pub fn select_receiver(&self) -> Address<N> {
        let mut rng = rand::thread_rng();

        let len = self.receivers.len();

        let idx = rng.gen_range(0..len);

        self.receivers[idx]
    }

    pub fn sync_and_serve(&self) {
        tracing::error_span!("FAST_SYNC").in_scope(|| {
            self.fast_sync().expect("failed to sync aleo");
            self.serve()
        })
    }

    pub fn serve(&self) {
        loop {
            if let Err(e) = self.sync() {
                tracing::error!("Failed to sync: {e}");
            }

            let executions = self.gen_transfer_executions();
            for e in executions {
                match self.handle_execution(e.clone()) {
                    Ok(result) => {
                        tracing::info!("✅ Execution of {e:?} broadcast successfully: {result}")
                    }
                    Err(err) => {
                        tracing::error!("❌ Execution of {e:?} failed to broadcast: {err}");
                        if !err.to_string().contains("already exists in the ledger")
                            && !err.to_string().contains("Fee record does not have enough")
                        {
                            let _ = self.handle_execution_failed(e);
                        }
                    }
                }
            }

            std::thread::sleep(Duration::from_secs(10));
        }
    }

    pub fn handle_execution_failed(&self, execution: TransferExecution<N>) -> anyhow::Result<()> {
        let TransferExecution {
            multi_idx,
            amount_record,
            fee_record,
            ..
        } = execution;

        self.multi[multi_idx]
            .records
            .insert(&amount_record.0, &amount_record.1)?;
        self.multi[multi_idx]
            .records
            .insert(&fee_record.0, &fee_record.1)?;

        Ok(())
    }
}

#[derive(Clone, Debug)]
pub struct TransferExecution<N: Network> {
    multi_idx: usize,
    receiver: Address<N>,
    amount: u64,
    amount_record: (String, Record<N, Plaintext<N>>),
    fee_record: (String, Record<N, Plaintext<N>>),
}
