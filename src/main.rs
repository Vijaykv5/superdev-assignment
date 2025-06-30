use axum::{routing::post, Json, Router, http::StatusCode, response::IntoResponse};
use serde::{Serialize, Deserialize};
use solana_sdk::signature::{Keypair, Signer};
use solana_sdk::bs58;
use solana_sdk::pubkey::Pubkey;
use tower_http::cors::{CorsLayer, Any};
use spl_token::instruction as token_instruction;
use base64::Engine;

#[derive(Serialize)]
struct ApiResponse<T> {
    success: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    data: Option<T>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
}

#[derive(Serialize)]
struct KeypairInfo {
    pubkey: String,
    secret: String,
}

#[derive(Serialize)]
struct InstructionData {
    program_id: String,
    accounts: Vec<AccountInfo>,
    instruction_data: String,
}

#[derive(Serialize)]
struct AccountInfo {
    pubkey: String,
    is_signer: bool,
    is_writable: bool,
}

#[derive(Deserialize)]
struct TokenCreateRequest {
    mint_authority: String,
    mint: String,
    decimals: u8,
}

// functions for parsing the publicky
fn parse_pubkey(pubkey_str: &str) -> Result<Pubkey, String> {
    let bytes = bs58::decode(pubkey_str)
        .into_vec()
        .map_err(|_| "Invalid public key format".to_string())?;
    
    Pubkey::try_from(bytes.as_slice())
        .map_err(|_| "Invalid public key".to_string())
}

fn instruction_to_response(instruction: solana_sdk::instruction::Instruction, program_id: Pubkey) -> InstructionData {
    let accounts: Vec<AccountInfo> = instruction.accounts.iter().map(|meta| {
        AccountInfo {
            pubkey: bs58::encode(meta.pubkey.as_ref()).into_string(),
            is_signer: meta.is_signer,
            is_writable: meta.is_writable,
        }
    }).collect();

    let instruction_data = base64::engine::general_purpose::STANDARD.encode(&instruction.data);

    InstructionData {
        program_id: bs58::encode(program_id.as_ref()).into_string(),
        accounts,
        instruction_data,
    }
}

async fn generate_keypair() -> impl IntoResponse {
    let keypair = Keypair::new();
    let pubkey = bs58::encode(keypair.pubkey().as_ref()).into_string();
    let secret = bs58::encode(keypair.to_bytes()).into_string();
    
    let response = ApiResponse {
        success: true,
        data: Some(KeypairInfo { pubkey, secret }),
        error: None,
    };
    
    (StatusCode::OK, Json(response))
}

async fn create_token(Json(req): Json<TokenCreateRequest>) -> impl IntoResponse {
    let mint_authority = match parse_pubkey(&req.mint_authority) {
        Ok(pk) => pk,
        Err(e) => {
            return (StatusCode::BAD_REQUEST, Json(ApiResponse::<InstructionData> {
                success: false,
                data: None,
                error: Some(e),
            }));
        }
    };

    let mint = match parse_pubkey(&req.mint) {
        Ok(pk) => pk,
        Err(e) => {
            return (StatusCode::BAD_REQUEST, Json(ApiResponse::<InstructionData> {
                success: false,
                data: None,
                error: Some(e),
            }));
        }
    };

    let instruction = token_instruction::initialize_mint(
        &spl_token::id(),
        &mint,
        &mint_authority,
        Some(&mint_authority),
        req.decimals,
    ).unwrap();

    let response = ApiResponse {
        success: true,
        data: Some(instruction_to_response(instruction, spl_token::id())),
        error: None,
    };

    (StatusCode::OK, Json(response))
}

#[tokio::main]
async fn main() {
    let cors = CorsLayer::new()
        .allow_origin(Any)
        .allow_methods([axum::http::Method::POST]);

    let app = Router::new()
        .route("/keypair", post(generate_keypair))
        .route("/token/create", post(create_token))
        .layer(cors);

    let addr: std::net::SocketAddr = "0.0.0.0:8082".parse().unwrap();
    println!("Server running on {}", addr);
    
    axum::serve(
        tokio::net::TcpListener::bind(addr).await.unwrap(),
        app.into_make_service()
    )
    .await
    .unwrap();
}
