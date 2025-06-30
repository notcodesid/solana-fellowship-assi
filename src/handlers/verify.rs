use axum::{http::StatusCode, response::Json, Json as JsonExtractor};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use solana_sdk::signature::Signature;
use solana_sdk::pubkey::Pubkey;

#[derive(Deserialize)]
pub struct VerifyRequest {
    message: String,
    signature: String,
    pubkey: String,
}

#[derive(Serialize)]
struct VerifyData {
    valid: bool,
    message: String,
    pubkey: String,
}

// verify a signed message
pub async fn verify_message(JsonExtractor(req): JsonExtractor<VerifyRequest>) -> Result<Json<Value>, StatusCode> {
    match verify_signature(&req.message, &req.signature, &req.pubkey) {
        Ok(is_valid) => {
            Ok(Json(json!({
                "success": true,
                "data": {
                    "valid": is_valid,
                    "message": req.message,
                    "pubkey": req.pubkey
                }
            })))
        }
        Err(error) => {
            eprintln!("error verifying message: {}", error);
            Ok(Json(json!({
                "success": false,
                "error": "invalid pubkey or signature"
            })))
        }
    }
}

// verify signature against message and public key
fn verify_signature(message: &str, signature_base64: &str, pubkey_str: &str) -> Result<bool, Box<dyn std::error::Error>> {
    // parse the public key
    let pubkey = pubkey_str.parse::<Pubkey>()?;
    
    // decode base64 signature
    let signature_bytes = base64::decode(signature_base64)?;
    
    // create signature from bytes
    let signature = Signature::try_from(signature_bytes.as_slice())?;
    
    // verify the signature
    let is_valid = signature.verify(pubkey.as_ref(), message.as_bytes());
    
    Ok(is_valid)
}

#[cfg(test)]
mod tests {
    use super::*;
    use solana_sdk::signer::{keypair::Keypair, Signer};
    
    #[test]
    fn test_verify_message() {
        // generate test keypair
        let keypair = Keypair::new();
        let public_key = keypair.pubkey().to_string();
        let message = "test message";
        
        // create signature
        let signature = keypair.sign_message(message.as_bytes());
        let signature_base64 = base64::encode(signature.as_ref());
        
        // test verification with correct signature
        let verify_result = verify_signature(message, &signature_base64, &public_key);
        assert!(verify_result.is_ok());
        assert!(verify_result.unwrap());
        
        // test verification with wrong message
        let wrong_verify = verify_signature("wrong message", &signature_base64, &public_key);
        assert!(wrong_verify.is_ok());
        assert!(!wrong_verify.unwrap());
        
        println!("verify test passed");
    }
} 