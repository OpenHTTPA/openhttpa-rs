// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright 2026 The OpenHTTPA Foundation (openhttpa.org)

function updateUI() {
  chrome.runtime.sendMessage({ type: 'GET_SESSIONS' }, (sessions) => {
    const list = document.getElementById('session-list');
    if (sessions && sessions.length > 0) {
      list.replaceChildren();
      sessions.forEach((s) => {
        const card = document.createElement('div');
        card.className = 'session-card';

        const originDiv = document.createElement('div');
        originDiv.className = 'origin';
        originDiv.textContent = s.origin;

        const statusDiv = document.createElement('div');
        statusDiv.className = 'status';

        const dot = document.createElement('span');
        dot.className = 'dot';
        statusDiv.appendChild(dot);
        statusDiv.appendChild(document.createTextNode(' Attested Session Active'));

        const idDiv = document.createElement('div');
        idDiv.style.fontSize = '10px';
        idDiv.style.color = '#64748b';
        idDiv.style.marginTop = '8px';
        idDiv.textContent = `Base ID: ${s.baseId}`;

        card.appendChild(originDiv);
        card.appendChild(statusDiv);
        card.appendChild(idDiv);

        list.appendChild(card);
      });
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
