use axum::{
    extract::ws::{Message, WebSocket, WebSocketUpgrade},
    response::Response,
};
use openhttpa_mcp::OpenHttpaMcpServer;

/// Upgrades the connection to WebSocket for Model Context Protocol (MCP) interactions.
pub async fn mcp_ws_handler(ws: WebSocketUpgrade) -> Response {
    ws.on_upgrade(handle_mcp_socket)
}

async fn handle_mcp_socket(mut socket: WebSocket) {
    let mcp_server = OpenHttpaMcpServer::new();

    while let Some(Ok(msg)) = socket.recv().await {
        if let Message::Text(text) = msg {
            match mcp_server.handle_request(text.as_bytes()).await {
                Ok(response_bytes) => {
                    if let Ok(response_text) = String::from_utf8(response_bytes) {
                        let _ = socket.send(Message::Text(response_text.into())).await;
                    }
                }
                Err(e) => {
                    tracing::error!("MCP handling error: {}", e);
                }
            }
        }
    }
}

pub mod aiql_pipeline;
