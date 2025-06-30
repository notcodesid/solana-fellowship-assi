use axum::{http::StatusCode, response::Json, Json as JsonExtractor};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use solana_sdk::signature::{Keypair, Signer};

#[derive(Deserialize)]
pub struct SignRequest {
    message: String,
    secret: String,
}

#[derive(Serialize)]
struct SignData {
    signature: String,
    public_key: String,
    message: String,
}

// sign a message using private key
pub async fn sign_message(JsonExtractor(req): JsonExtractor<SignRequest>) -> Result<Json<Value>, StatusCode> {
    match create_signature(&req.message, &req.secret) {
        Ok((signature, public_key)) => {
            Ok(Json(json!({
                "success": true,
                "data": {
                    "signature": signature,
                    "public_key": public_key,
                    "message": req.message
                }
            })))
        }
        Err(error) => {
            eprintln!("error signing message: {}", error);
            Ok(Json(json!({
                "success": false,
                "error": "invalid secret key format"
            })))
        }
    }
}

// create signature for message using base58 secret key
fn create_signature(message: &str, secret_key: &str) -> Result<(String, String), Box<dyn std::error::Error>> {
    // decode base58 secret key
    let secret_bytes = bs58::decode(secret_key).into_vec()?;
    
    // check secret key length is 64 bytes
    if secret_bytes.len() != 64 {
        return Err("invalid secret key length".into());
    }
    
    // create keypair from secret bytes
    let keypair = Keypair::from_bytes(&secret_bytes)?;
    
    // sign the message
    let signature = keypair.sign_message(message.as_bytes());
    
    // encode signature as base64
    let signature_base64 = base64::encode(signature.as_ref());
    
    // get public key as base58 string
    let public_key = keypair.pubkey().to_string();
    
    Ok((signature_base64, public_key))
}

#[cfg(test)]
mod tests {
    use super::*;
    use solana_sdk::signer::keypair::Keypair;
    
    #[test]
    fn test_sign_message() {
        // generate test keypair
        let keypair = Keypair::new();
        let secret_key = bs58::encode(keypair.to_bytes()).into_string();
        let public_key = keypair.pubkey().to_string();
        let message = "test message";
        
        // test signing
        let sign_result = create_signature(message, &secret_key);
        assert!(sign_result.is_ok());
        
        let (signature, returned_pubkey) = sign_result.unwrap();
        assert_eq!(returned_pubkey, public_key);
        assert!(!signature.is_empty());
        
        println!("sign test passed");
    }
} 