// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright 2026 The OpenHTTPA Foundation

use crate::store::MemoryStore;
use openhttpa_mcp::server::McpTool;
use serde_json::{Value, json};
use std::future::Future;
use std::pin::Pin;

pub struct FabricReadTool {
    pub store: MemoryStore,
}

impl McpTool for FabricReadTool {
    fn name(&self) -> &str {
        "fabric_read"
    }

    fn description(&self) -> Option<&str> {
        Some("Retrieve context from the shared memory fabric")
    }

    fn input_schema(&self) -> Value {
        json!({
            "type": "object",
            "properties": {
                "namespace": { "type": "string" },
                "key": { "type": "string" }
            },
            "required": ["namespace", "key"]
        })
    }

    fn call<'a>(
        &'a self,
        arguments: Value,
    ) -> Pin<Box<dyn Future<Output = Result<Value, String>> + Send + 'a>> {
        Box::pin(async move {
            let namespace = arguments
                .get("namespace")
                .and_then(Value::as_str)
                .ok_or("Missing namespace")?;
            let key = arguments
                .get("key")
                .and_then(Value::as_str)
                .ok_or("Missing key")?;

            if let Some(data) = self.store.get(namespace, key) {
                let data_str =
                    String::from_utf8(data).unwrap_or_else(|_| "[Binary Data]".to_string());
                Ok(json!({ "value": data_str }))
            } else {
                Err("Key not found".to_string())
            }
        })
    }
}

pub struct FabricWriteTool {
    pub store: MemoryStore,
}

impl McpTool for FabricWriteTool {
    fn name(&self) -> &str {
        "fabric_write"
    }

    fn description(&self) -> Option<&str> {
        Some("Store new insights or context into the shared memory fabric")
    }

    fn input_schema(&self) -> Value {
        json!({
            "type": "object",
            "properties": {
                "namespace": { "type": "string" },
                "key": { "type": "string" },
                "value": { "type": "string" }
            },
            "required": ["namespace", "key", "value"]
        })
    }

    fn call<'a>(
        &'a self,
        arguments: Value,
    ) -> Pin<Box<dyn Future<Output = Result<Value, String>> + Send + 'a>> {
        Box::pin(async move {
            let namespace = arguments
                .get("namespace")
                .and_then(Value::as_str)
                .ok_or("Missing namespace")?;
            let key = arguments
                .get("key")
                .and_then(Value::as_str)
                .ok_or("Missing key")?;
            let value = arguments
                .get("value")
                .and_then(Value::as_str)
                .ok_or("Missing value")?;

            let timestamp = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();

            let mut vv = crate::store::VersionVector::new();
            vv.insert("mcp_agent".to_string(), timestamp);

            self.store
                .put(namespace, key, value.as_bytes().to_vec(), vv, None);
            Ok(json!({ "status": "success" }))
        })
    }
}
