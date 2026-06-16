use async_graphql::*;
use openhttpa_zk::{ZkReceipt, verifier::ZkVerifier};
use sha2::{Digest, Sha384};
use std::collections::HashMap;
use std::sync::{Mutex, OnceLock};

fn mock_db() -> &'static Mutex<HashMap<String, f64>> {
    static DB: OnceLock<Mutex<HashMap<String, f64>>> = OnceLock::new();
    DB.get_or_init(|| {
        let mut m = HashMap::new();
        m.insert("alice".to_string(), 1000.0);
        Mutex::new(m)
    })
}

#[derive(Default)]
pub struct FinanceQuery;

#[Object]
impl FinanceQuery {
    async fn get_balance(&self, _ctx: &Context<'_>, account_id: String) -> Result<f64> {
        let db = mock_db().lock().unwrap();
        Ok(db.get(&account_id).copied().unwrap_or(0.0))
    }
}

#[derive(Default)]
pub struct FinanceMutation;

#[Object]
impl FinanceMutation {
    async fn relay_finance_intent(
        &self,
        _ctx: &Context<'_>,
        encrypted_intent: String,
        tx_proof: String,
    ) -> Result<bool> {
        let proof_bytes =
            hex::decode(&tx_proof).map_err(|e| Error::new(format!("Invalid proof hex: {}", e)))?;

        let receipt: ZkReceipt = postcard::from_bytes(&proof_bytes)
            .map_err(|e| Error::new(format!("Invalid proof format: {}", e)))?;

        // Compute actual transcript hash instead of a placeholder
        let mut hasher = Sha384::new();
        hasher.update(encrypted_intent.as_bytes());
        let mut transcript_hash = [0u8; 48];
        transcript_hash.copy_from_slice(&hasher.finalize());

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

    async fn submit_transaction(&self, _ctx: &Context<'_>, tx_data: String) -> Result<String> {
        tracing::info!("Mock backend processing transaction: {}", tx_data);
        let tx_hash = hex::encode(Sha384::digest(tx_data.as_bytes()));
        Ok(tx_hash)
    }
}
