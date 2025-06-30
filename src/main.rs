use axum::{
    http::StatusCode,
    response::Json,
    routing::get,
    Router,
};
use serde_json::{json, Value};
use tower_http::cors::CorsLayer;

#[tokio::main]
async fn main() {
    // Initialize the router
    let app = Router::new()
        .route("/", get(root_handler))
        .layer(CorsLayer::permissive());

    // Define the server address
    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000")
        .await
        .unwrap();

    println!("hello solana fellowship members :D");

    // Start the server
    axum::serve(listener, app)
        .await
        .unwrap();
}

// Basic root handler to verify server is running
async fn root_handler() -> Result<Json<Value>, StatusCode> {
    Ok(Json(json!({
        "message": "hello solana fellowship members :D",
        "status": "running",
        "version": "1.0.0",
        "endpoints": "coming soon..."
    })))    
}
