// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright 2026 The OpenHTTPA Foundation (AIQL.org)

function updateUI() {
  chrome.runtime.sendMessage({ type: 'GET_SESSIONS' }, (sessions) => {
    const list = document.getElementById('session-list');
    if (sessions && sessions.length > 0) {
      list.innerHTML = sessions
        .map(
          (s) => `
                <div class="session-card">
                    <div class="origin">${s.origin}</div>
                    <div class="status">
                        <span class="dot"></span>
                        Attested Session Active
                    </div>
                    <div style="font-size: 10px; color: #64748b; margin-top: 8px;">
                        Base ID: ${s.baseId}
                    </div>
                </div>
            `,
        )
        .join('');
    }
  });
}

// Initial update
updateUI();

// Listen for updates from background
chrome.runtime.onMessage.addListener((msg) => {
  if (msg.type === 'SESSION_ESTABLISHED') {
    updateUI();
  }
});
