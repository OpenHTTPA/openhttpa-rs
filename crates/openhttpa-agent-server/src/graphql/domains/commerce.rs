use async_graphql::*;

#[derive(Default)]
pub struct CommerceMutation;

#[Object]
impl CommerceMutation {
    async fn zk_ad_match(&self, _ctx: &Context<'_>, _zk_ad_preferences: String) -> Result<bool> {
        // TODO: The server blindly matches ads based on ZK preferences.
        Ok(true)
    }
}
