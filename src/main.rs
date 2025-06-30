use hyper::{Body, Request, Response, Server, Method, StatusCode};
use hyper::service::{make_service_fn, service_fn};
use std::convert::Infallible;
use serde::{Serialize, Deserialize};
use solana_sdk::signature::{Keypair, Signature, Signer, read_keypair_file};
use solana_sdk::pubkey::Pubkey;
use bs58;
use base64;
use serde_json::json;
use solana_sdk::system_instruction;
use solana_sdk::instruction::Instruction;


#[derive(Serialize)]
struct KeypairResponse {
    success: bool,
    data: KeypairData,
}

#[derive(Serialize)]
struct KeypairData {
    pubkey: String,
    secret: String,
}

#[derive(Deserialize)]
struct SignRequest {
    message: String,
    secret: String,
}

#[derive(Serialize)]
struct SignResponse {
    success: bool,
    data: Option<SignData>,
    error: Option<String>,
}

#[derive(Serialize)]
struct SignData {
    signature: String,
    public_key: String,
    message: String,
}

#[derive(Deserialize)]
struct VerifyRequest {
    message: String,
    signature: String,
    pubkey: String,
}

#[derive(Serialize)]
struct VerifyResponse {
    success: bool,
    data: Option<VerifyData>,
    error: Option<String>,
}

#[derive(Serialize)]
struct VerifyData {
    valid: bool,
    message: String,
    pubkey: String,
}

#[derive(Deserialize)]
struct SendSolRequest {
    from: String,
    to: String,
    lamports: u64,
}

#[derive(Serialize)]
struct SendSolResponse {
    success: bool,
    data: Option<SendSolData>,
    error: Option<String>,
}

#[derive(Serialize)]
struct SendSolData {
    program_id: String,
    accounts: Vec<String>,
    instruction_data: String,
}
async fn handle_request(req: Request<Body>) -> Result<Response<Body>, Infallible> {
    let (method, path) = (req.method(), req.uri().path());

    match (method, path) {
        // GET /
        (&Method::GET, "/") => Ok(Response::new(Body::from("Welcome to the Rust HTTP server!"))),

        // GET /hello
        (&Method::GET, "/hello") => Ok(Response::new(Body::from("Hello from Rust!"))),

        // GET /health
        (&Method::GET, "/health") => Ok(Response::new(Body::from("OK"))),

        // POST /keypair
        (&Method::POST, "/keypair") => {
            let keypair = Keypair::new();
            let pubkey = keypair.pubkey().to_string();
            let secret = bs58::encode(keypair.to_bytes()).into_string();

            let response = KeypairResponse {
                success: true,
                data: KeypairData { pubkey, secret },
            };

            let json = serde_json::to_string(&response).unwrap();

            Ok(Response::builder()
                .header("Content-Type", "application/json")
                .status(StatusCode::OK)
                .body(Body::from(json))
                .unwrap())
        }
                // POST /send/sol
                (&Method::POST, "/send/sol") => {
                    let body_bytes = hyper::body::to_bytes(req.into_body()).await.unwrap();
                    let parsed: Result<SendSolRequest, _> = serde_json::from_slice(&body_bytes);
        
                    match parsed {
                        Ok(req_data) => {
                            // Validate from/to as Pubkeys
                            let from = req_data.from.parse::<Pubkey>();
                            let to = req_data.to.parse::<Pubkey>();
        
                            if let (Ok(from_pubkey), Ok(to_pubkey)) = (from, to) {
                                // Build the transfer instruction
                                let ix: Instruction = system_instruction::transfer(&from_pubkey, &to_pubkey, req_data.lamports);
        
                                let encoded_data = base64::encode(&ix.data);
        
                                let data = SendSolData {
                                    program_id: ix.program_id.to_string(),
                                    accounts: ix.accounts.iter().map(|a| a.pubkey.to_string()).collect(),
                                    instruction_data: encoded_data,
                                };
        
                                let json = serde_json::to_string(&SendSolResponse {
                                    success: true,
                                    data: Some(data),
                                    error: None,
                                }).unwrap();
        
                                return Ok(Response::builder()
                                    .header("Content-Type", "application/json")
                                    .status(StatusCode::OK)
                                    .body(Body::from(json))
                                    .unwrap());
                            }
        
                            // Invalid pubkeys
                            let err_json = serde_json::to_string(&SendSolResponse {
                                success: false,
                                data: None,
                                error: Some("Invalid from/to public keys".to_string()),
                            }).unwrap();
        
                            Ok(Response::builder()
                                .header("Content-Type", "application/json")
                                .status(StatusCode::BAD_REQUEST)
                                .body(Body::from(err_json))
                                .unwrap())
                        }
        
                        Err(_) => {
                            let err_json = serde_json::to_string(&SendSolResponse {
                                success: false,
                                data: None,
                                error: Some("Missing or invalid fields".to_string()),
                            }).unwrap();
        
                            Ok(Response::builder()
                                .header("Content-Type", "application/json")
                                .status(StatusCode::BAD_REQUEST)
                                .body(Body::from(err_json))
                                .unwrap())
                        }
                    }
                }
        

        // POST /message/sign
        (&Method::POST, "/message/sign") => {
            let body_bytes = hyper::body::to_bytes(req.into_body()).await.unwrap();
            let parsed: Result<SignRequest, _> = serde_json::from_slice(&body_bytes);

            match parsed {
                Ok(sign_req) => {
                    let decoded = bs58::decode(sign_req.secret).into_vec();

                    if let Ok(secret_bytes) = decoded {
                        if secret_bytes.len() == 64 {
                            if let Ok(keypair) = Keypair::from_bytes(&secret_bytes) {
                                let signature = keypair.sign_message(sign_req.message.as_bytes());
                                let signature_base64 = base64::encode(signature.as_ref());

                                let data = SignData {
                                    signature: signature_base64,
                                    public_key: keypair.pubkey().to_string(),
                                    message: sign_req.message,
                                };

                                let json = serde_json::to_string(&SignResponse {
                                    success: true,
                                    data: Some(data),
                                    error: None,
                                }).unwrap();

                                return Ok(Response::builder()
                                    .header("Content-Type", "application/json")
                                    .status(StatusCode::OK)
                                    .body(Body::from(json))
                                    .unwrap());
                            }
                        }
                    }

                    let error_json = serde_json::to_string(&SignResponse {
                        success: false,
                        data: None,
                        error: Some("Invalid secret key format".into()),
                    }).unwrap();

                    Ok(Response::builder()
                        .header("Content-Type", "application/json")
                        .status(StatusCode::BAD_REQUEST)
                        .body(Body::from(error_json))
                        .unwrap())
                }

                Err(_) => {
                    let error_json = json!({
                        "success": false,
                        "error": "Missing required fields"
                    }).to_string();

                    Ok(Response::builder()
                        .header("Content-Type", "application/json")
                        .status(StatusCode::BAD_REQUEST)
                        .body(Body::from(error_json))
                        .unwrap())
                }
            }
        }

        // POST /message/verify
        (&Method::POST, "/message/verify") => {
            let body_bytes = hyper::body::to_bytes(req.into_body()).await.unwrap();
            let parsed: Result<VerifyRequest, _> = serde_json::from_slice(&body_bytes);

            match parsed {
                Ok(verify_req) => {
                    let pubkey_result = verify_req.pubkey.parse::<Pubkey>();
                    let sig_result = base64::decode(&verify_req.signature);

                    if let (Ok(pubkey), Ok(signature_bytes)) = (pubkey_result, sig_result) {
                        if let Ok(signature) = Signature::try_from(signature_bytes.as_slice()) {
                            let valid = signature.verify(pubkey.as_ref(), verify_req.message.as_bytes());

                            let data = VerifyData {
                                valid,
                                message: verify_req.message,
                                pubkey: pubkey.to_string(),
                            };

                            let json = serde_json::to_string(&VerifyResponse {
                                success: true,
                                data: Some(data),
                                error: None,
                            }).unwrap();

                            return Ok(Response::builder()
                                .header("Content-Type", "application/json")
                                .status(StatusCode::OK)
                                .body(Body::from(json))
                                .unwrap());
                        }
                    }

                    let error_json = serde_json::to_string(&VerifyResponse {
                        success: false,
                        data: None,
                        error: Some("Invalid pubkey or signature".into()),
                    }).unwrap();

                    Ok(Response::builder()
                        .header("Content-Type", "application/json")
                        .status(StatusCode::BAD_REQUEST)
                        .body(Body::from(error_json))
                        .unwrap())
                }

                Err(_) => {
                    let error_json = json!({
                        "success": false,
                        "error": "Missing required fields"
                    }).to_string();

                    Ok(Response::builder()
                        .header("Content-Type", "application/json")
                        .status(StatusCode::BAD_REQUEST)
                        .body(Body::from(error_json))
                        .unwrap())
                }
            }
        }

        // fallback 404
        _ => {
            let mut not_found = Response::default();
            *not_found.status_mut() = StatusCode::NOT_FOUND;
            Ok(not_found)
        }
    }
}

#[tokio::main]
async fn main() {
    let addr = ([127, 0, 0, 1], 3000).into();

    let make_svc = make_service_fn(|_conn| async {
        Ok::<_, Infallible>(service_fn(handle_request))
    });

    let server = Server::bind(&addr).serve(make_svc);

    println!("Listening on http://{}", addr);

    if let Err(e) = server.await {
        eprintln!("server error: {}", e);
    }
}