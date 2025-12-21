//! Cross-Layer RPC - TCP Socket for L1↔L2 Communication
//!
//! Simple TCP socket server for L2 to verify L1 state.
//! Protocol: JSON over TCP with newline delimiter.

use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tokio::net::{TcpListener, TcpStream};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

pub const CROSS_LAYER_PORT: u16 = 8091;

#[derive(Debug, Serialize, Deserialize)]
pub struct Request {
    pub method: String,
    pub params: serde_json::Value,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Response {
    pub success: bool,
    pub data: serde_json::Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

impl Response {
    pub fn ok(data: serde_json::Value) -> Self {
        Response { success: true, data, error: None }
    }
    pub fn err(msg: &str) -> Self {
        Response { success: false, data: serde_json::Value::Null, error: Some(msg.to_string()) }
    }
}

/// Cross-layer RPC server (L2 calls this to verify L1 state)
pub struct CrossLayerServer {
    port: u16,
}

impl CrossLayerServer {
    pub fn new(port: Option<u16>) -> Self {
        Self { port: port.unwrap_or(CROSS_LAYER_PORT) }
    }

    pub async fn start(self: Arc<Self>) -> Result<(), String> {
        let addr = format!("127.0.0.1:{}", self.port);
        let listener = TcpListener::bind(&addr).await
            .map_err(|e| format!("Bind failed: {}", e))?;
        
        println!("🌉 Cross-layer RPC on {}", addr);

        loop {
            if let Ok((stream, _)) = listener.accept().await {
                let server = Arc::clone(&self);
                tokio::spawn(async move {
                    let _ = server.handle(stream).await;
                });
            }
        }
    }

    async fn handle(&self, stream: TcpStream) -> Result<(), String> {
        let (reader, mut writer) = stream.into_split();
        let mut reader = BufReader::new(reader);
        let mut line = String::new();

        loop {
            line.clear();
            match reader.read_line(&mut line).await {
                Ok(0) => break,
                Ok(_) => {
                    let response = self.process(&line);
                    let json = serde_json::to_string(&response).unwrap_or_default();
                    let _ = writer.write_all(format!("{}\n", json).as_bytes()).await;
                }
                Err(_) => break,
            }
        }
        Ok(())
    }

    fn process(&self, line: &str) -> Response {
        let req: Request = match serde_json::from_str(line.trim()) {
            Ok(r) => r,
            Err(e) => return Response::err(&format!("Parse error: {}", e)),
        };

        match req.method.as_str() {
            "ping" => Response::ok(serde_json::json!({ "pong": true })),
            "verify_balance" => {
                // L2 asks: does this address have >= amount on L1?
                let addr = req.params.get("address").and_then(|v| v.as_str()).unwrap_or("");
                let _amount = req.params.get("amount").and_then(|v| v.as_f64()).unwrap_or(0.0);
                // In production: check actual blockchain state
                Response::ok(serde_json::json!({
                    "address": addr,
                    "verified": true,
                    "timestamp": std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_secs()
                }))
            }
            _ => Response::err(&format!("Unknown method: {}", req.method)),
        }
    }
}

/// Client for L2 to call L1
pub struct CrossLayerClient {
    addr: String,
}

impl CrossLayerClient {
    pub fn new(host: &str, port: u16) -> Self {
        Self { addr: format!("{}:{}", host, port) }
    }

    pub fn localhost() -> Self {
        Self::new("127.0.0.1", CROSS_LAYER_PORT)
    }

    pub async fn call(&self, method: &str, params: serde_json::Value) -> Result<Response, String> {
        let stream = TcpStream::connect(&self.addr).await
            .map_err(|e| format!("Connect failed: {}", e))?;
        
        let (reader, mut writer) = stream.into_split();
        let mut reader = BufReader::new(reader);

        let req = Request { method: method.to_string(), params };
        let json = serde_json::to_string(&req).map_err(|e| e.to_string())?;
        
        writer.write_all(format!("{}\n", json).as_bytes()).await
            .map_err(|e| format!("Write failed: {}", e))?;

        let mut line = String::new();
        reader.read_line(&mut line).await
            .map_err(|e| format!("Read failed: {}", e))?;

        serde_json::from_str(&line).map_err(|e| format!("Parse failed: {}", e))
    }

    pub async fn ping(&self) -> Result<bool, String> {
        let resp = self.call("ping", serde_json::json!({})).await?;
        Ok(resp.success)
    }

    pub async fn verify_balance(&self, address: &str, amount: f64) -> Result<bool, String> {
        let resp = self.call("verify_balance", serde_json::json!({
            "address": address,
            "amount": amount
        })).await?;
        Ok(resp.data.get("verified").and_then(|v| v.as_bool()).unwrap_or(false))
    }
}
