use std::{
    io::Read,
    path::{Path, PathBuf},
    str::FromStr,
};

use aleo_rust::{Address, PrivateKey, Testnet3};
use clap::Parser;

use crate::multi::MultiManager;

#[derive(Debug, Parser)]
pub struct MultiCli {
    #[clap(long)]
    pub pks_path: PathBuf,

    #[clap(long)]
    pub receiver_path: PathBuf,

    #[clap(long)]
    pub aleo_rpc: Option<String>,

    #[clap(long)]
    pub from_height: Option<u32>,
}

impl MultiCli {
    pub fn parse(self) {
        let Self {
            pks_path,
            receiver_path,
            aleo_rpc,
            from_height,
        } = self;

        let pks = get_from_line::<PrivateKey<Testnet3>>(pks_path).expect("read file");
        let addrs = get_from_line::<Address<Testnet3>>(receiver_path).expect("read file");
        let m = MultiManager::new(aleo_rpc, pks, addrs, from_height).expect("init manager");
        m.sync_and_serve()
    }
}

pub fn get_from_line<T: FromStr>(path: impl AsRef<Path>) -> anyhow::Result<Vec<T>> {
    let mut file = std::fs::File::open(path)?;

    let mut buf = String::new();
    file.read_to_string(&mut buf)?;
    let mut list = vec![];

    buf.lines().for_each(|l| {
        if let Ok(t) = T::from_str(l) {
            list.push(t);
        }
    });

    Ok(list)
}
