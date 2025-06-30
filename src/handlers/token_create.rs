use axum::{http::StatusCode, response::Json, Json as JsonExtractor};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use solana_sdk::{
    instruction::{AccountMeta, Instruction},
    pubkey::Pubkey,
    system_program,
    sysvar,
};
use spl_token::{instruction, state::Mint};

#[derive(Deserialize)]
pub struct CreateTokenRequest {
    #[serde(rename = "mintAuthority")]
    mint_authority: String,
    mint: String,
    decimals: u8,
}

#[derive(Serialize)]
struct AccountInfo {
    pubkey: String,
    is_signer: bool,
    is_writable: bool,
}

// create new spl token mint instruction
pub async fn create_token(JsonExtractor(req): JsonExtractor<CreateTokenRequest>) -> Result<Json<Value>, StatusCode> {
    match build_mint_instruction(&req.mint_authority, &req.mint, req.decimals) {
        Ok((program_id, accounts, instruction_data)) => {
            Ok(Json(json!({
                "success": true,
                "data": {
                    "program_id": program_id,
                    "accounts": accounts,
                    "instruction_data": instruction_data
                }
            })))
        }
        Err(error) => {
            eprintln!("error creating token: {}", error);
            Ok(Json(json!({
                "success": false,
                "error": "invalid mint authority or mint address"
            })))
        }
    }
}

// build mint initialization instruction
fn build_mint_instruction(
    mint_authority: &str,
    mint: &str,
    decimals: u8,
) -> Result<(String, Vec<AccountInfo>, String), Box<dyn std::error::Error>> {
    // parse addresses
    let mint_authority_pubkey = mint_authority.parse::<Pubkey>()?;
    let mint_pubkey = mint.parse::<Pubkey>()?;

    // create initialize mint instruction
    let instruction = instruction::initialize_mint(
        &spl_token::id(),
        &mint_pubkey,
        &mint_authority_pubkey,
        Some(&mint_authority_pubkey), // freeze authority same as mint authority
        decimals,
    )?;

    // convert accounts to our format
    let accounts: Vec<AccountInfo> = instruction
        .accounts
        .iter()
        .map(|acc| AccountInfo {
            pubkey: acc.pubkey.to_string(),
            is_signer: acc.is_signer,
            is_writable: acc.is_writable,
        })
        .collect();

    // encode instruction data as base64
    let instruction_data = base64::encode(&instruction.data);

    Ok((
        spl_token::id().to_string(),
        accounts,
        instruction_data,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use solana_sdk::signer::{keypair::Keypair, Signer};

    #[test]
    fn test_build_mint_instruction() {
        // generate test keypairs
        let mint_authority = Keypair::new();
        let mint = Keypair::new();

        let result = build_mint_instruction(
            &mint_authority.pubkey().to_string(),
            &mint.pubkey().to_string(),
            6,
        );

        assert!(result.is_ok());

        let (program_id, accounts, instruction_data) = result.unwrap();

        // check program id is spl token program
        assert_eq!(program_id, spl_token::id().to_string());

        // check we have accounts
        assert!(!accounts.is_empty());

        // check instruction data is valid base64
        assert!(base64::decode(&instruction_data).is_ok());

        println!("token create test passed");
    }
} 