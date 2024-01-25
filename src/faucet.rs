use std::io::Read;
use std::net::SocketAddr;
use std::path::Path;
use std::str::FromStr;

use aleo_rust::{
    Address, AleoAPIClient, Literal, Network, Plaintext, PrivateKey, ProgramManager, TransferType,
    Value,
};
use axum::{extract::State, http::StatusCode, routing::post, Json, Router};
use serde::{Deserialize, Serialize};
use tower_http::cors::Any;
use tower_http::{cors::CorsLayer, trace, trace::TraceLayer};
use tracing::Level;

const MIN_EXEC_FEE: u64 = 20000000;

pub fn retry_with_times(
    times: usize,
    mut f: impl FnMut() -> anyhow::Result<()>,
) -> anyhow::Result<()> {
    for _ in 0..times {
        if f().is_ok() {
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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransferExecution {
    address: String,
    amount: u64,
}

#[derive(Clone)]
pub struct AleoExecutor<N: Network> {
    account: Address<N>,
    pm: ProgramManager<N>,
}

impl<N: Network> AleoExecutor<N> {
    pub fn new(aleo_rpc: Option<String>, pk: PrivateKey<N>) -> anyhow::Result<Self> {
        let aleo_client = match aleo_rpc {
            Some(aleo_rpc) => AleoAPIClient::new(&aleo_rpc, "testnet3")?,
            None => AleoAPIClient::testnet3(),
        };

        let account = Address::try_from(pk.clone())?;

        let pm = ProgramManager::new(Some(pk), None, Some(aleo_client.clone()), None, true)?;
        Ok(Self { pm, account })
    }

    pub async fn initial(self, addr: SocketAddr) -> anyhow::Result<()> {
        let node = self.clone();
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
            .route("/tranfer", post(transfer))
            .with_state(node)
            .layer(cors)
            .layer(
                TraceLayer::new_for_http()
                    .make_span_with(trace::DefaultMakeSpan::new().level(Level::INFO))
                    .on_response(trace::DefaultOnResponse::new().level(Level::INFO)),
            );

        tracing::info!("relayer listening on {}", addr);
        let listener = tokio::net::TcpListener::bind(addr).await?;
        axum::serve(listener, router.into_make_service()).await?;
        Ok(())
    }

    pub fn execute(&mut self, exec: Execution) -> anyhow::Result<String> {
        if self.get_balance()? < MIN_EXEC_FEE {
            return Err(anyhow::anyhow!("balance not enough"));
        }
        let result = self.pm.execute_program(
            exec.program_id,
            exec.program_function,
            exec.inputs.iter(),
            exec.fee,
            None,
            None,
        );

        result
    }

    pub fn transfer(&mut self, addr: String, amount: u64) -> anyhow::Result<(String, String)> {
        if self.get_balance()? < amount {
            return Err(anyhow::anyhow!("balance not enough"));
        }
        let addr: Address<N> = Address::<N>::from_str(&addr)?;
        tracing::warn!("transfering to {} amount {amount}", addr);

        let result =
            self.pm
                .transfer(amount, 0, addr, TransferType::Public, None, None, None)?;

        Ok((addr.to_string(), result))
    }

    pub fn add_nft(&mut self, nft_id: String) -> anyhow::Result<(String, String)> {
        tracing::warn!("adding nft {nft_id}");

        let nft_input = from_nft_id(nft_id.clone());

        let inputs = vec![nft_input, "0scalar".to_string()];

        let result = self.pm.execute_program(
            "izar_testnet3_nft_v1.aleo",
            "add_nft",
            inputs.iter(),
            40000,
            None,
            None,
        )?;

        Ok((nft_id, result))
    }

    pub fn add_white_list(&mut self, addr: String) -> anyhow::Result<(String, String)> {
        tracing::warn!("adding white list {addr}");

        let inputs = vec![addr.to_string(), "1u8".to_string()];

        let result = self.pm.execute_program(
            "izar_testnet3_nft_v1.aleo",
            "add_minter",
            inputs.iter(),
            40000,
            None,
            None,
        )?;

        Ok((addr, result))
    }

    pub fn get_balance(&self) -> anyhow::Result<u64> {
        let key = Plaintext::from_str(&self.account.to_string())?;
        let v = self
            .client()
            .get_mapping_value("credits.aleo", "account", key)?;
        if let Value::Plaintext(p) = v {
            if let Plaintext::Literal(Literal::U64(v), _) = p {
                Ok(*v)
            } else {
                Err(anyhow::anyhow!("get balance error"))
            }
        } else {
            Err(anyhow::anyhow!("get balance error"))
        }
    }

    pub fn client(&self) -> &AleoAPIClient<N> {
        self.pm.api_client().unwrap()
    }
}

async fn exec<N: Network>(
    State(mut node): State<AleoExecutor<N>>,
    Json(req): Json<Execution>,
) -> anyhow::Result<Json<String>, (StatusCode, String)> {
    let tid = node.execute(req).map_err(|e| {
        tracing::error!("failed to execute: {}", e);
        (StatusCode::INTERNAL_SERVER_ERROR, e.to_string())
    })?;

    Ok(Json(tid))
}

async fn transfer<N: Network>(
    State(mut node): State<AleoExecutor<N>>,
    Json(req): Json<TransferExecution>,
) -> anyhow::Result<Json<(String, String)>, (StatusCode, String)> {
    let (addr, tid) = node.transfer(req.address, req.amount).map_err(|e| {
        tracing::error!("failed to transfer: {}", e);
        (StatusCode::INTERNAL_SERVER_ERROR, e.to_string())
    })?;

    Ok(Json((addr, tid)))
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
