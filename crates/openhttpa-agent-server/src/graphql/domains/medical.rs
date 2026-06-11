use async_graphql::*;

#[derive(Default)]
pub struct MedicalMutation;

#[Object]
impl MedicalMutation {
    async fn store_attested_record(
        &self,
        _ctx: &Context<'_>,
        _encrypted_record_id: String,
        _tee_attestation: String,
    ) -> Result<bool> {
        // TODO: Verify TEE attestation using openhttpa-tee.
        Ok(true)
    }
}
