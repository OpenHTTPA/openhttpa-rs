use async_graphql_axum::{GraphQLProtocol, GraphQLRequest, GraphQLResponse, GraphQLWebSocket};
use axum::{
    Router,
    extract::{State, ws::WebSocketUpgrade},
    http::HeaderMap,
    response::Response,
    routing::{get, post},
};
use std::net::SocketAddr;
use tracing::info;

mod agent;
mod auth;
mod graphql;
mod state;

use graphql::{AppSchema, build_schema};
use state::AppState;

async fn graphql_handler(
    schema: State<AppSchema>,
    headers: HeaderMap,
    req: GraphQLRequest,
) -> GraphQLResponse {
    let mut req = req.into_inner();

    // Extract simulated client posture from headers for demo/testing
    use openhttpa_proto::{ClientSecurityPosture, TeeClass};
    let posture = match headers
        .get("x-simulate-client-posture")
        .and_then(|h| h.to_str().ok())
    {
        Some("MutualTee") => ClientSecurityPosture::MutualTee(TeeClass::IntelTdx),
        Some("SimulatedTee") => ClientSecurityPosture::SimulatedTee,
        _ => ClientSecurityPosture::OneDirectional, // Default
    };
    req = req.data(posture);

    schema.execute(req).await.into()
}

async fn graphql_ws_handler(
    schema: State<AppSchema>,
    protocol: GraphQLProtocol,
    websocket: WebSocketUpgrade,
) -> Response {
    websocket
        .protocols(["graphql-transport-ws", "graphql-ws"])
        .on_upgrade(move |stream| GraphQLWebSocket::new(stream, schema.0.clone(), protocol).serve())
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt::init();

    let app_state = AppState::new().await?;
    let schema = build_schema();

    let app = Router::new()
        // Unified GraphQL endpoint
        .route("/graphql", post(graphql_handler))
        // GraphQL subscriptions
        .route("/graphql/ws", get(graphql_ws_handler))
        // MCP Agent endpoint
        .route("/mcp", get(agent::mcp_ws_handler))
        .with_state(schema)
        .with_state(app_state);

    // SECURITY: Servers MUST listen on localhost or 127.0.0.1 when testing.
    let addr = SocketAddr::from(([127, 0, 0, 1], 8081));
    info!("openhttpa-agent-server listening on {}", addr);

    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app).await?;

    Ok(())
}
