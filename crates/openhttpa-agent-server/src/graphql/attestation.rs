use async_graphql::*;
use base64ct::Encoding;
use openhttpa_proto::QuoteType;
use openhttpa_proto::ReportData;
use openhttpa_tee::{QuoteRequest, mock::MockTeeProvider, provider::TeeProvider};
use sha2::{Digest, Sha384};

#[derive(SimpleObject)]
pub struct AgentAttestationQuote {
    pub quote_type: String,
    pub raw_base64: String,
    pub qudd_base64: String,
    pub collateral_uris: Vec<String>,
}

#[derive(Default)]
pub struct AttestationQuery;

#[Object]
impl AttestationQuery {
    async fn get_agent_attestation(
        &self,
        _ctx: &Context<'_>,
        nonce: String,
    ) -> Result<AgentAttestationQuote> {
        // Compute SHA-384 of the nonce for the ReportData
        let mut hasher = Sha384::new();
        hasher.update(nonce.as_bytes());
        let digest_result = hasher.finalize();

        let mut digest_bytes = [0u8; 48];
        digest_bytes.copy_from_slice(&digest_result);

        let report_data = ReportData::from_sha384(&digest_bytes);

        // Use MockTeeProvider simulated as TDX
        let provider = MockTeeProvider::with_override(QuoteType::Tdx);

        let req = QuoteRequest {
            report_data: *report_data.as_bytes(),
        };

        let quote = provider
            .generate_quote(&req)
            .map_err(|e| Error::new(format!("Failed to generate TEE quote: {}", e)))?;

        Ok(AgentAttestationQuote {
            quote_type: quote.quote_type.to_string(),
            raw_base64: quote.raw_base64(),
            qudd_base64: base64ct::Base64::encode_string(&quote.qudd),
            collateral_uris: quote.collateral_uris.clone(),
        })
    }
}
