use async_graphql::*;
use openhttpa_zk::{ZkReceipt, verifier::ZkVerifier};

#[derive(Default)]
pub struct CommerceMutation;

#[Object]
impl CommerceMutation {
    async fn zk_ad_match(&self, _ctx: &Context<'_>, zk_ad_preferences: String) -> Result<bool> {
        let proof_bytes = hex::decode(&zk_ad_preferences)
            .map_err(|e| Error::new(format!("Invalid proof hex: {}", e)))?;

        let receipt: ZkReceipt = postcard::from_bytes(&proof_bytes)
            .map_err(|e| Error::new(format!("Invalid proof format: {}", e)))?;

        let transcript_hash = [0u8; 48];

        match ZkVerifier::verify(&receipt, &transcript_hash) {
            Ok(output) => {
                if !output.is_valid {
                    return Err(Error::new(
                        "ZK ad preference verification failed: receipt invalid",
                    ));
                }
                tracing::info!("ZK Ad Preference matched successfully!");
            }
            Err(e) => return Err(Error::new(format!("ZK verification error: {}", e))),
        }

        Ok(true)
    }
}
