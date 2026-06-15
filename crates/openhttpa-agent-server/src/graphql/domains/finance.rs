use async_graphql::*;
use openhttpa_zk::{ZkReceipt, verifier::ZkVerifier};

#[derive(Default)]
pub struct FinanceQuery;

#[Object]
impl FinanceQuery {
    async fn get_balance(&self, _ctx: &Context<'_>, _account_id: String) -> Result<f64> {
        // TODO: integrate with backend
        Ok(100.0)
    }
}

#[derive(Default)]
pub struct FinanceMutation;

#[Object]
impl FinanceMutation {
    async fn relay_finance_intent(
        &self,
        _ctx: &Context<'_>,
        _encrypted_intent: String,
        tx_proof: String,
    ) -> Result<bool> {
        let proof_bytes =
            hex::decode(&tx_proof).map_err(|e| Error::new(format!("Invalid proof hex: {}", e)))?;

        let receipt: ZkReceipt = postcard::from_bytes(&proof_bytes)
            .map_err(|e| Error::new(format!("Invalid proof format: {}", e)))?;

        // Note: For now, we use a placeholder transcript hash for the application data
        let transcript_hash = [0u8; 48];

        match ZkVerifier::verify(&receipt, &transcript_hash) {
            Ok(output) => {
                if !output.is_valid {
                    return Err(Error::new("ZK verification failed: receipt marked invalid"));
                }
                tracing::info!("Finance intent ZK proof verified successfully.");
            }
            Err(e) => return Err(Error::new(format!("ZK verification error: {}", e))),
        }

        Ok(true)
    }

    async fn submit_transaction(&self, _ctx: &Context<'_>, _tx_data: String) -> Result<String> {
        // TODO: integrate with backend
        Ok("tx_hash".to_string())
    }
}
