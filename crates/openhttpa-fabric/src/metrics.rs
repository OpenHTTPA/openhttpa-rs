// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright 2026 The OpenHTTPA Foundation

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

/// A simple in-memory metrics registry for the OpenHTTPA Fabric.
#[derive(Clone, Default)]
pub struct FabricMetrics {
    pub aiql_evaluations_total: Arc<AtomicU64>,
    pub gossip_syncs_total: Arc<AtomicU64>,
    pub memory_distillation_events: Arc<AtomicU64>,
}

impl FabricMetrics {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn inc_aiql_evaluations(&self) {
        self.aiql_evaluations_total.fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_gossip_syncs(&self) {
        self.gossip_syncs_total.fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_memory_distillation(&self) {
        self.memory_distillation_events
            .fetch_add(1, Ordering::Relaxed);
    }

    pub fn snapshot(&self) -> (u64, u64, u64) {
        (
            self.aiql_evaluations_total.load(Ordering::Relaxed),
            self.gossip_syncs_total.load(Ordering::Relaxed),
            self.memory_distillation_events.load(Ordering::Relaxed),
        )
    }
}
