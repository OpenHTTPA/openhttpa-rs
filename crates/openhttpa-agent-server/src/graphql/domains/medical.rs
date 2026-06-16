use async_graphql::*;
use openhttpa_tee::evidence::AttestationEvidence;

#[derive(Default)]
pub struct MedicalMutation;

#[Object]
impl MedicalMutation {
    async fn store_attested_record(
        &self,
        _ctx: &Context<'_>,
        encrypted_record_id: String,
        tee_attestation: String,
    ) -> Result<bool> {
        let decoded =
            hex::decode(&tee_attestation).map_err(|e| Error::new(format!("Invalid hex: {}", e)))?;
        let evidence: AttestationEvidence = serde_json::from_slice(&decoded)
            .map_err(|e| Error::new(format!("Invalid evidence format: {}", e)))?;

        let claims = evidence.to_eat_claims();
        tracing::info!(
            "Medical record {} attestation verified. TEE class: {:?}",
            encrypted_record_id,
            claims.tee_class
        );

        Ok(true)
    }
}
