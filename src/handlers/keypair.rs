use axum::{http::StatusCode, response::Json};
use serde_json::{json, Value};
use solana_sdk::signer::{keypair::Keypair, Signer};

// generate a new solana keypair
pub async fn generate_keypair() -> Result<Json<Value>, StatusCode> {
    match create_new_keypair() {
        Ok((pubkey, secret)) => {
            Ok(Json(json!({
                "success": true,
                "data": {
                    "pubkey": pubkey,
                    "secret": secret
                }
            })))
        }
        Err(error) => {
            eprintln!("error generating keypair: {}", error);
            Ok(Json(json!({
                "success": false,
                "error": "failed to generate keypair"
            })))
        }
    }
}

// create new solana keypair and return base58 encoded keys
fn create_new_keypair() -> Result<(String, String), Box<dyn std::error::Error>> {
    // generate a new keypair
    let keypair = Keypair::new();
    
    // get public key as base58 string
    let pubkey = keypair.pubkey().to_string();
    
    // get secret key as base58 string
    let secret = bs58::encode(&keypair.to_bytes()).into_string();
    
    Ok((pubkey, secret))
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_create_new_keypair() {
        let result = create_new_keypair();
        assert!(result.is_ok());
        
        let (pubkey, secret) = result.unwrap();
        
        // check that both strings are base58 encoded
        assert!(!pubkey.is_empty());
        assert!(!secret.is_empty());
        assert!(bs58::decode(&pubkey).into_vec().is_ok());
        assert!(bs58::decode(&secret).into_vec().is_ok());
        
        println!("generated pubkey: {}", pubkey);
        println!("generated secret: {}", secret);
    }
} 