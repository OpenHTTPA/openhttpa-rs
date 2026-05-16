// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright 2026 The OpenHTTPA Foundation (AIQL.org)

import init, {
  openhttpa_initiate_attest,
  openhttpa_derive_session,
  openhttpa_seal,
  openhttpa_unseal,
} from './wasm/openhttpa_wasm.js';

let wasmInitialized = false;
let activeSessions = new Map(); // host -> sessionData

// Initialize Wasm and load persistent state
async function ensureWasm() {
  if (!wasmInitialized) {
    await init();
    wasmInitialized = true;

    // Restore sessions from storage
    const stored = await chrome.storage.session.get('activeSessions');
    if (stored.activeSessions) {
      for (const [origin, data] of Object.entries(stored.activeSessions)) {
        // [Expert C Hardening] Sanitize restored data
        if (typeof origin === 'string' && data.baseId && /^[0-9a-fA-F-]+$/.test(data.baseId)) {
          activeSessions.set(origin, data);
        }
      }
      console.log('[OpenHTTPA] Restored and sanitized sessions:', activeSessions.size);
      await updateDnrRules();
    }
  }
}

async function persistSessions() {
  const data = Object.fromEntries(activeSessions);
  await chrome.storage.session.set({ activeSessions: data });
}

/**
 * Protocol Probing (Phase 1)
 * Intercept OPTIONS requests to detect OpenHTTPA support.
 */
chrome.webRequest.onHeadersReceived.addListener(
  async (details) => {
    if (details.method === 'OPTIONS') {
      const h = details.responseHeaders.find((x) => x.name.toLowerCase() === 'attest-versions');
      if (h && h.value.includes('openhttpa')) {
        console.log('[OpenHTTPA] Detected capable server:', details.url);
        await establishSession(new URL(details.url).origin);
      }
    }
  },
  { urls: ['<all_urls>'] },
  ['responseHeaders'],
);

/**
 * Handshake Execution (Phase 2)
 */
async function establishSession(origin) {
  await ensureWasm();

  console.log('[OpenHTTPA] Initiating handshake with', origin);
  const clientJson = openhttpa_initiate_attest();

  try {
    const resp = await fetch(`${origin}/api/attest`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: clientJson,
    });

    const serverJson = await resp.text();
    const sessionProofStr = openhttpa_derive_session(serverJson);
    const sessionProof = JSON.parse(sessionProofStr);

    activeSessions.set(origin, {
      baseId: sessionProof.base_id,
      origin: origin,
      timestamp: Date.now(),
    });

    await persistSessions();
    await updateDnrRules();

    console.log('[OpenHTTPA] Session established! BaseID:', sessionProof.base_id);

    // Notify popup/UI
    chrome.runtime.sendMessage({
      type: 'SESSION_ESTABLISHED',
      origin,
      baseId: sessionProof.base_id,
    });
  } catch (e) {
    console.error('[OpenHTTPA] Handshake failed:', e);
  }
}

/**
 * Request Interception & Encryption (Phase 4 - TrR)
 */
/**
 * Session Tagging (Phase 4 - TrR)
 * In Manifest V3, we use declarativeNetRequest to safely add session headers.
 */
async function updateDnrRules() {
  const rules = Array.from(activeSessions.values()).map((session, index) => ({
    id: index + 1,
    priority: 1,
    action: {
      type: 'modifyHeaders',
      requestHeaders: [
        { header: 'Attest-Base-ID', operation: 'set', value: session.baseId },
        { header: 'Attest-Versions', operation: 'set', value: 'openhttpa' },
      ],
    },
    condition: {
      urlFilter: session.origin + '/*',
      resourceTypes: ['main_frame', 'sub_frame', 'xmlhttprequest'],
    },
  }));

  // Remove old rules and add new ones
  const oldRules = await chrome.declarativeNetRequest.getDynamicRules();
  const oldIds = oldRules.map((r) => r.id);

  await chrome.declarativeNetRequest.updateDynamicRules({
    removeRuleIds: oldIds,
    addRules: rules,
  });

  console.log('[OpenHTTPA] Updated DNR rules for', rules.length, 'sessions');
}

// Listen for messages from popup
chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  if (msg.type === 'GET_SESSIONS') {
    sendResponse(Array.from(activeSessions.values()));
  }
});
