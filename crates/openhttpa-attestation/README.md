# openhttpa-attestation

Verification logic for TEE attestation quotes and evidence.

This crate provides a pluggable system for verifying attestation quotes from various Trusted Execution Environments (TEEs). It is used by both clients (to verify the server) and servers (in mutual attestation scenarios).

## Supported Verifiers

- **Mock**: A testing verifier that accepts any quote. Useful for development without TEE hardware.
- **Azure MAA**: Support for Microsoft Azure Attestation service.
- **Intel DCAP**: Local and remote verification for SGX and TDX quotes.
- **AMD SNP**: Support for AMD SEV-SNP attestation reports.

## Core Trait: `QuoteVerifier`

The central abstraction is the `QuoteVerifier` trait:

```rust
#[async_trait]
pub trait QuoteVerifier: Send + Sync {
    async fn verify(
        &self,
        quote: &AttestQuote,
        report_data: &[u8; 64],
    ) -> Result<VerificationResult, VerificationError>;
}
```

## Verification Process

1.  **Extract Evidence**: The verifier parses the raw quote bytes.
2.  **Validate Signatures**: It checks the certificate chain and signature on the quote.
3.  **Check Freshness**: It ensures the `report_data` (which contains the transcript hash in `OpenHTTPA`) matches the expected value.
4.  **TCB Evaluation**: It evaluates the Trust Compute Base (TCB) status and ensures the hardware is in a secure state.

## Integration

Used by `openhttpa-core` and `openhttpa-server` to enforce attestation policies during the handshake phase.
