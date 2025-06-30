use axum::{
    http::StatusCode,
    response::Json,
    routing::{get, post},
    Router,
};
use serde_json::{json, Value};
use tower_http::cors::CorsLayer;
use std::env;

mod handlers;

#[tokio::main]
async fn main() {
    // setup router with endpoints
    let app = Router::new()
        .route("/", get(root_handler))
        .route("/keypair", post(handlers::keypair::generate_keypair))
        .route("/message/sign", post(handlers::sign::sign_message))
        .route("/message/verify", post(handlers::verify::verify_message))
        .route("/token/create", post(handlers::token_create::create_token))
        .layer(CorsLayer::permissive());

    // get port from environment or use default
    let port = env::var("PORT").unwrap_or_else(|_| "3000".to_string());
    let addr = format!("0.0.0.0:{}", port);

    // bind server to address
    let listener = tokio::net::TcpListener::bind(&addr)
        .await
        .unwrap();

    println!("hello solana fellowship members :D");
    println!("server running on {}", addr);
    println!("available endpoints:");
    println!("  POST /keypair - generate new solana keypair");
    println!("  POST /message/sign - sign a message with private key");
    println!("  POST /message/verify - verify a signed message");
    println!("  POST /token/create - create spl token mint instruction");

    // start the server
    axum::serve(listener, app)
        .await
        .unwrap();
}

// basic handler to check server status
async fn root_handler() -> Result<Json<Value>, StatusCode> {
    Ok(Json(json!({
        "message": "hello solana fellowship members :D",
        "status": "running",
        "version": "1.0.0",
        "endpoints": {
            "POST /keypair": "generate new solana keypair",
            "POST /message/sign": "sign a message with private key",
            "POST /message/verify": "verify a signed message",
            "POST /token/create": "create spl token mint instruction"
        }
    })))
}
