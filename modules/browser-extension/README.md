# `OpenHTTPA` Browser Extension

This extension enables `OpenHTTPA` (HTTP with Attestation) support in standard Chromium-based browsers (Chrome, Edge, Brave). It handles background handshakes and request/response transformation, allowing legacy web applications to benefit from hardware-attested security.

## Features

- **Manifest V3**: Uses modern, secure extension APIs.
- **Background Handshake**: Automatically performs SIGMA-I handshakes with discovered `OpenHTTPA` endpoints.
- **Request Interception**: Injects `Attest-Base-ID` and AEAD tags into outbound requests.
- **Security Indicator**: Displays the hardware attestation status (Mock, SGX, TDX, etc.) in the browser toolbar.
- **Protocol Discovery**: Detects `OpenHTTPA` support via `OPTIONS` probes and `Attest-Versions` headers.

## Installation

1. Clone this repository.
2. Open Chrome and go to `chrome://extensions`.
3. Enable **Developer mode**.
4. Click **Load unpacked** and select this directory.

## Usage

Once installed, the extension will monitor all network traffic. When it encounters a server advertising `OpenHTTPA` support:

1. It will initiate a handshake with `/api/attest`.
2. Upon success, the `OpenHTTPA` icon will turn blue.
3. Subsequent requests to that origin will be upgraded to `OpenHTTPA`.

## Development

- `background.js`: Core protocol logic and network interception.
- `manifest.json`: Extension metadata and permissions.
- `popup.html`: The UI for viewing session status.
- `icons/`: Protocol status icons.
