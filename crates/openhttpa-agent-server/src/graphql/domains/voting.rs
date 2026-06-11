use async_graphql::*;

#[derive(Default)]
pub struct VotingMutation;

#[Object]
impl VotingMutation {
    async fn submit_blind_vote(
        &self,
        _ctx: &Context<'_>,
        _blind_signature: String,
        _zk_snark_proof: String,
    ) -> Result<bool> {
        // TODO: Verify the blind signature prevents double voting.
        Ok(true)
    }
}
