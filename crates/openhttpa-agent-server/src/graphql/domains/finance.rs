use async_graphql::*;

#[derive(Default)]
pub struct FinanceMutation;

#[Object]
impl FinanceMutation {
    async fn relay_finance_intent(
        &self,
        _ctx: &Context<'_>,
        _encrypted_intent: String,
        _tx_proof: String,
    ) -> Result<bool> {
        // TODO: Verify ZK proof using openhttpa-zk.
        Ok(true)
    }
}
