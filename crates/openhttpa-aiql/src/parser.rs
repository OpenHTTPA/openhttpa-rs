// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright 2026 The OpenHTTPA Foundation

use crate::AiqlPolicy;
use serde_json::Error as SerdeError;

pub struct AiqlParser;

impl AiqlParser {
    pub fn parse_json(json: &str) -> Result<AiqlPolicy, SerdeError> {
        serde_json::from_str(json)
    }
}
