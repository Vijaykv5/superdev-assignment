use axum::{routing::post, Json, Router, http::StatusCode, response::IntoResponse};
use serde::{Serialize, Deserialize};
use solana_sdk::signature::{Keypair, Signer};
use solana_sdk::bs58;
use solana_sdk::pubkey::Pubkey;
use solana_sdk::system_instruction;
use tower_http::cors::{CorsLayer, Any};
use spl_token::instruction as token_instruction;
use base64::Engine;

#[derive(Serialize)]
struct KeypairResponse {
    success: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    data: Option<KeypairData>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
}

#[derive(Serialize)]
struct KeypairData {
    pubkey: String,
    secret: String,
}

#[derive(Deserialize)]
struct CreateTokenRequest {
    #[serde(rename = "mintAuthority")]
    mint_authority: String,
    mint: String,
    decimals: u8,
}

#[derive(Deserialize)]
struct MintTokenRequest {
    mint: String,
    destination: String,
    authority: String,
    amount: u64,
}

#[derive(Deserialize)]
struct SignMessageRequest {
    message: String,
    secret: String,
}

#[derive(Deserialize)]
struct VerifyMessageRequest {
    message: String,
    signature: String,
    pubkey: String,
}

#[derive(Deserialize)]
struct SendSolRequest {
    from: String,
    to: String,
    lamports: u64,
}

#[derive(Deserialize)]
struct SendTokenRequest {
    destination: String,
    mint: String,
    owner: String,
    amount: u64,
}

#[derive(Serialize)]
struct CreateTokenResponse {
    success: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    data: Option<TokenData>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
}

#[derive(Serialize)]
struct MintTokenResponse {
    success: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    data: Option<TokenData>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
}

#[derive(Serialize)]
struct SignMessageResponse {
    success: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    data: Option<SignMessageData>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
}

#[derive(Serialize)]
struct VerifyMessageResponse {
    success: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    data: Option<VerifyMessageData>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
}

#[derive(Serialize)]
struct SendSolResponse {
    success: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    data: Option<SendSolData>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
}

#[derive(Serialize)]
struct SendTokenResponse {
    success: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    data: Option<SendTokenData>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
}

#[derive(Serialize)]
struct TokenData {
    program_id: String,
    accounts: Vec<AccountMeta>,
    instruction_data: String,
}

#[derive(Serialize)]
struct AccountMeta {
    pubkey: String,
    is_signer: bool,
    is_writable: bool,
}

#[derive(Serialize)]
struct SendSolData {
    program_id: String,
    accounts: Vec<String>,
    instruction_data: String,
}

#[derive(Serialize)]
struct SendTokenData {
    program_id: String,
    accounts: Vec<SendTokenAccountMeta>,
    instruction_data: String,
}

#[derive(Serialize)]
struct SendTokenAccountMeta {
    pubkey: String,
    #[serde(rename = "isSigner")]
    is_signer: bool,
}

#[derive(Serialize)]
struct SignMessageData {
    signature: String,
    public_key: String,
    message: String,
}

#[derive(Serialize)]
struct VerifyMessageData {
    valid: bool,
    message: String,
    pubkey: String,
}

async fn generate_keypair() -> impl IntoResponse {
    let keypair = Keypair::new();
    let pubkey = bs58::encode(keypair.pubkey().as_ref()).into_string();
    let secret = bs58::encode(keypair.to_bytes()).into_string();
    let response = KeypairResponse {
        success: true,
        data: Some(KeypairData { pubkey, secret }),
        error: None,
    };
    (StatusCode::OK, Json(response))
}

async fn create_token(
    Json(payload): Json<CreateTokenRequest>,
) -> impl IntoResponse {
    // Parse the provided public keys
    let mint_authority = match bs58::decode(&payload.mint_authority).into_vec() {
        Ok(bytes) => match Pubkey::try_from(bytes.as_slice()) {
            Ok(pubkey) => pubkey,
            Err(_) => {
                let response = CreateTokenResponse {
                    success: false,
                    data: None,
                    error: Some("Invalid mint authority public key".to_string()),
                };
                return (StatusCode::BAD_REQUEST, Json(response));
            }
        },
        Err(_) => {
            let response = CreateTokenResponse {
                success: false,
                data: None,
                error: Some("Invalid mint authority public key format".to_string()),
            };
            return (StatusCode::BAD_REQUEST, Json(response));
        }
    };

    let mint = match bs58::decode(&payload.mint).into_vec() {
        Ok(bytes) => match Pubkey::try_from(bytes.as_slice()) {
            Ok(pubkey) => pubkey,
            Err(_) => {
                let response = CreateTokenResponse {
                    success: false,
                    data: None,
                    error: Some("Invalid mint public key".to_string()),
                };
                return (StatusCode::BAD_REQUEST, Json(response));
            }
        },
        Err(_) => {
            let response = CreateTokenResponse {
                success: false,
                data: None,
                error: Some("Invalid mint public key format".to_string()),
            };
            return (StatusCode::BAD_REQUEST, Json(response));
        }
    };

    // Create the mint initialization instruction
    let instruction = token_instruction::initialize_mint(
        &spl_token::id(),
        &mint,
        &mint_authority,
        Some(&mint_authority),
        payload.decimals,
    ).unwrap();

    // Convert instruction to the required format
    let accounts: Vec<AccountMeta> = instruction.accounts.iter().map(|meta| {
        AccountMeta {
            pubkey: bs58::encode(meta.pubkey.as_ref()).into_string(),
            is_signer: meta.is_signer,
            is_writable: meta.is_writable,
        }
    }).collect();

    let instruction_data = base64::engine::general_purpose::STANDARD.encode(&instruction.data);

    let response = CreateTokenResponse {
        success: true,
        data: Some(TokenData {
            program_id: bs58::encode(spl_token::id().as_ref()).into_string(),
            accounts,
            instruction_data,
        }),
        error: None,
    };

    (StatusCode::OK, Json(response))
}

async fn mint_token(
    Json(payload): Json<MintTokenRequest>,
) -> impl IntoResponse {
    // Parse the provided public keys
    let mint = match bs58::decode(&payload.mint).into_vec() {
        Ok(bytes) => match Pubkey::try_from(bytes.as_slice()) {
            Ok(pubkey) => pubkey,
            Err(_) => {
                let response = MintTokenResponse {
                    success: false,
                    data: None,
                    error: Some("Invalid mint public key".to_string()),
                };
                return (StatusCode::BAD_REQUEST, Json(response));
            }
        },
        Err(_) => {
            let response = MintTokenResponse {
                success: false,
                data: None,
                error: Some("Invalid mint public key format".to_string()),
            };
            return (StatusCode::BAD_REQUEST, Json(response));
        }
    };

    let destination = match bs58::decode(&payload.destination).into_vec() {
        Ok(bytes) => match Pubkey::try_from(bytes.as_slice()) {
            Ok(pubkey) => pubkey,
            Err(_) => {
                let response = MintTokenResponse {
                    success: false,
                    data: None,
                    error: Some("Invalid destination public key".to_string()),
                };
                return (StatusCode::BAD_REQUEST, Json(response));
            }
        },
        Err(_) => {
            let response = MintTokenResponse {
                success: false,
                data: None,
                error: Some("Invalid destination public key format".to_string()),
            };
            return (StatusCode::BAD_REQUEST, Json(response));
        }
    };

    let authority = match bs58::decode(&payload.authority).into_vec() {
        Ok(bytes) => match Pubkey::try_from(bytes.as_slice()) {
            Ok(pubkey) => pubkey,
            Err(_) => {
                let response = MintTokenResponse {
                    success: false,
                    data: None,
                    error: Some("Invalid authority public key".to_string()),
                };
                return (StatusCode::BAD_REQUEST, Json(response));
            }
        },
        Err(_) => {
            let response = MintTokenResponse {
                success: false,
                data: None,
                error: Some("Invalid authority public key format".to_string()),
            };
            return (StatusCode::BAD_REQUEST, Json(response));
        }
    };

    // Create the mint-to instruction
    let instruction = token_instruction::mint_to(
        &spl_token::id(),
        &mint,
        &destination,
        &authority,
        &[],
        payload.amount,
    ).unwrap();

    // Convert instruction to the required format
    let accounts: Vec<AccountMeta> = instruction.accounts.iter().map(|meta| {
        AccountMeta {
            pubkey: bs58::encode(meta.pubkey.as_ref()).into_string(),
            is_signer: meta.is_signer,
            is_writable: meta.is_writable,
        }
    }).collect();

    let instruction_data = base64::engine::general_purpose::STANDARD.encode(&instruction.data);

    let response = MintTokenResponse {
        success: true,
        data: Some(TokenData {
            program_id: bs58::encode(spl_token::id().as_ref()).into_string(),
            accounts,
            instruction_data,
        }),
        error: None,
    };

    (StatusCode::OK, Json(response))
}

async fn sign_message(
    Json(payload): Json<SignMessageRequest>,
) -> impl IntoResponse {
    // Validate required fields
    if payload.message.is_empty() || payload.secret.is_empty() {
        let response = SignMessageResponse {
            success: false,
            data: None,
            error: Some("Missing required fields".to_string()),
        };
        return (StatusCode::BAD_REQUEST, Json(response));
    }

    // Parse the secret key
    let secret_bytes = match bs58::decode(&payload.secret).into_vec() {
        Ok(bytes) => bytes,
        Err(_) => {
            let response = SignMessageResponse {
                success: false,
                data: None,
                error: Some("Invalid secret key format".to_string()),
            };
            return (StatusCode::BAD_REQUEST, Json(response));
        }
    };

    // Create keypair from secret key
    let keypair = match Keypair::from_bytes(&secret_bytes) {
        Ok(kp) => kp,
        Err(_) => {
            let response = SignMessageResponse {
                success: false,
                data: None,
                error: Some("Invalid secret key".to_string()),
            };
            return (StatusCode::BAD_REQUEST, Json(response));
        }
    };

    // Sign the message
    let message_bytes = payload.message.as_bytes();
    let signature = keypair.sign_message(message_bytes);
    
    let response = SignMessageResponse {
        success: true,
        data: Some(SignMessageData {
            signature: base64::engine::general_purpose::STANDARD.encode(signature.as_ref()),
            public_key: bs58::encode(keypair.pubkey().as_ref()).into_string(),
            message: payload.message,
        }),
        error: None,
    };

    (StatusCode::OK, Json(response))
}

async fn verify_message(
    Json(payload): Json<VerifyMessageRequest>,
) -> impl IntoResponse {
    // Validate required fields
    if payload.message.is_empty() || payload.signature.is_empty() || payload.pubkey.is_empty() {
        let response = VerifyMessageResponse {
            success: false,
            data: None,
            error: Some("Missing required fields".to_string()),
        };
        return (StatusCode::BAD_REQUEST, Json(response));
    }

    // Parse the public key
    let public_key = match bs58::decode(&payload.pubkey).into_vec() {
        Ok(bytes) => match Pubkey::try_from(bytes.as_slice()) {
            Ok(pubkey) => pubkey,
            Err(_) => {
                let response = VerifyMessageResponse {
                    success: false,
                    data: None,
                    error: Some("Invalid public key".to_string()),
                };
                return (StatusCode::BAD_REQUEST, Json(response));
            }
        },
        Err(_) => {
            let response = VerifyMessageResponse {
                success: false,
                data: None,
                error: Some("Invalid public key format".to_string()),
            };
            return (StatusCode::BAD_REQUEST, Json(response));
        }
    };

    // Parse the signature
    let signature_bytes = match base64::engine::general_purpose::STANDARD.decode(&payload.signature) {
        Ok(bytes) => bytes,
        Err(_) => {
            let response = VerifyMessageResponse {
                success: false,
                data: None,
                error: Some("Invalid signature format".to_string()),
            };
            return (StatusCode::BAD_REQUEST, Json(response));
        }
    };

    let signature = match solana_sdk::signature::Signature::try_from(signature_bytes.as_slice()) {
        Ok(sig) => sig,
        Err(_) => {
            let response = VerifyMessageResponse {
                success: false,
                data: None,
                error: Some("Invalid signature".to_string()),
            };
            return (StatusCode::BAD_REQUEST, Json(response));
        }
    };

    // Verify the signature
    let message_bytes = payload.message.as_bytes();
    let is_valid = signature.verify(public_key.as_ref(), message_bytes);

    let response = VerifyMessageResponse {
        success: true,
        data: Some(VerifyMessageData {
            valid: is_valid,
            message: payload.message,
            pubkey: payload.pubkey,
        }),
        error: None,
    };

    (StatusCode::OK, Json(response))
}

async fn send_sol(
    Json(payload): Json<SendSolRequest>,
) -> impl IntoResponse {
    // Validate required fields
    if payload.from.is_empty() || payload.to.is_empty() {
        let response = SendSolResponse {
            success: false,
            data: None,
            error: Some("Missing required fields".to_string()),
        };
        return (StatusCode::BAD_REQUEST, Json(response));
    }

    // Validate lamports amount
    if payload.lamports == 0 {
        let response = SendSolResponse {
            success: false,
            data: None,
            error: Some("Lamports amount must be greater than 0".to_string()),
        };
        return (StatusCode::BAD_REQUEST, Json(response));
    }

    // Parse the from address
    let from_pubkey = match bs58::decode(&payload.from).into_vec() {
        Ok(bytes) => match Pubkey::try_from(bytes.as_slice()) {
            Ok(pubkey) => pubkey,
            Err(_) => {
                let response = SendSolResponse {
                    success: false,
                    data: None,
                    error: Some("Invalid from address".to_string()),
                };
                return (StatusCode::BAD_REQUEST, Json(response));
            }
        },
        Err(_) => {
            let response = SendSolResponse {
                success: false,
                data: None,
                error: Some("Invalid from address format".to_string()),
            };
            return (StatusCode::BAD_REQUEST, Json(response));
        }
    };

    // Parse the to address
    let to_pubkey = match bs58::decode(&payload.to).into_vec() {
        Ok(bytes) => match Pubkey::try_from(bytes.as_slice()) {
            Ok(pubkey) => pubkey,
            Err(_) => {
                let response = SendSolResponse {
                    success: false,
                    data: None,
                    error: Some("Invalid to address".to_string()),
                };
                return (StatusCode::BAD_REQUEST, Json(response));
            }
        },
        Err(_) => {
            let response = SendSolResponse {
                success: false,
                data: None,
                error: Some("Invalid to address format".to_string()),
            };
            return (StatusCode::BAD_REQUEST, Json(response));
        }
    };

    // Validate that from and to addresses are different
    if from_pubkey == to_pubkey {
        let response = SendSolResponse {
            success: false,
            data: None,
            error: Some("From and to addresses must be different".to_string()),
        };
        return (StatusCode::BAD_REQUEST, Json(response));
    }

    // Create the SOL transfer instruction
    let instruction = system_instruction::transfer(&from_pubkey, &to_pubkey, payload.lamports);

    // Convert instruction to the required format - just the account addresses
    let accounts: Vec<String> = instruction.accounts.iter().map(|meta| {
        bs58::encode(meta.pubkey.as_ref()).into_string()
    }).collect();

    let instruction_data = base64::engine::general_purpose::STANDARD.encode(&instruction.data);

    let response = SendSolResponse {
        success: true,
        data: Some(SendSolData {
            program_id: bs58::encode(solana_sdk::system_program::id().as_ref()).into_string(),
            accounts,
            instruction_data,
        }),
        error: None,
    };

    (StatusCode::OK, Json(response))
}

async fn send_token(
    Json(payload): Json<SendTokenRequest>,
) -> impl IntoResponse {
    // Validate required fields
    if payload.destination.is_empty() || payload.mint.is_empty() || payload.owner.is_empty() {
        let response = SendTokenResponse {
            success: false,
            data: None,
            error: Some("Missing required fields".to_string()),
        };
        return (StatusCode::BAD_REQUEST, Json(response));
    }
    
    if payload.amount == 0 {
        let response = SendTokenResponse {
            success: false,
            data: None,
            error: Some("Amount must be greater than 0".to_string()),
        };
        return (StatusCode::BAD_REQUEST, Json(response));
    }
    
    // Parse addresses
    let destination_pubkey = match bs58::decode(&payload.destination).into_vec() {
        Ok(bytes) => match Pubkey::try_from(bytes.as_slice()) {
            Ok(pubkey) => pubkey,
            Err(_) => {
                let response = SendTokenResponse {
                    success: false,
                    data: None,
                    error: Some("Invalid destination address".to_string()),
                };
                return (StatusCode::BAD_REQUEST, Json(response));
            }
        },
        Err(_) => {
            let response = SendTokenResponse {
                success: false,
                data: None,
                error: Some("Invalid destination address format".to_string()),
            };
            return (StatusCode::BAD_REQUEST, Json(response));
        }
    };
    
    let mint_pubkey = match bs58::decode(&payload.mint).into_vec() {
        Ok(bytes) => match Pubkey::try_from(bytes.as_slice()) {
            Ok(pubkey) => pubkey,
            Err(_) => {
                let response = SendTokenResponse {
                    success: false,
                    data: None,
                    error: Some("Invalid mint address".to_string()),
                };
                return (StatusCode::BAD_REQUEST, Json(response));
            }
        },
        Err(_) => {
            let response = SendTokenResponse {
                success: false,
                data: None,
                error: Some("Invalid mint address format".to_string()),
            };
            return (StatusCode::BAD_REQUEST, Json(response));
        }
    };
    
    let owner_pubkey = match bs58::decode(&payload.owner).into_vec() {
        Ok(bytes) => match Pubkey::try_from(bytes.as_slice()) {
            Ok(pubkey) => pubkey,
            Err(_) => {
                let response = SendTokenResponse {
                    success: false,
                    data: None,
                    error: Some("Invalid owner address".to_string()),
                };
                return (StatusCode::BAD_REQUEST, Json(response));
            }
        },
        Err(_) => {
            let response = SendTokenResponse {
                success: false,
                data: None,
                error: Some("Invalid owner address format".to_string()),
            };
            return (StatusCode::BAD_REQUEST, Json(response));
        }
    };
    
    // Validate that destination and owner are different
    if destination_pubkey == owner_pubkey {
        let response = SendTokenResponse {
            success: false,
            data: None,
            error: Some("Destination and owner must be different".to_string()),
        };
        return (StatusCode::BAD_REQUEST, Json(response));
    }
    
    // Create the SPL token transfer instruction
    let instruction = match token_instruction::transfer(
        &spl_token::id(),
        &owner_pubkey,
        &destination_pubkey,
        &owner_pubkey,
        &[],
        payload.amount,
    ) {
        Ok(ix) => ix,
        Err(_) => {
            let response = SendTokenResponse {
                success: false,
                data: None,
                error: Some("Failed to create transfer instruction".to_string()),
            };
            return (StatusCode::INTERNAL_SERVER_ERROR, Json(response));
        }
    };

    // Convert instruction to the required format - with isSigner field
    let accounts: Vec<SendTokenAccountMeta> = instruction.accounts.iter().map(|meta| {
        SendTokenAccountMeta {
            pubkey: bs58::encode(meta.pubkey.as_ref()).into_string(),
            is_signer: meta.is_signer,
        }
    }).collect();
    
    let instruction_data = base64::engine::general_purpose::STANDARD.encode(&instruction.data);
    
    let response = SendTokenResponse {
        success: true,
        data: Some(SendTokenData {
            program_id: bs58::encode(spl_token::id().as_ref()).into_string(),
            accounts,
            instruction_data,
        }),
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
        .route("/token/mint", post(mint_token))
        .route("/message/sign", post(sign_message))
        .route("/message/verify", post(verify_message))
        .route("/send/sol", post(send_sol))
        .route("/send/token", post(send_token))
        .layer(cors);

    let addr: std::net::SocketAddr = "0.0.0.0:8082".parse().unwrap();
    println!("Listening on {}", addr);
    axum::serve(
        tokio::net::TcpListener::bind(addr).await.unwrap(),
        app.into_make_service()
    )
    .await
    .unwrap();
}
