use async_graphql::*;
use openhttpa_zk::{ZkReceipt, verifier::ZkVerifier};
use std::collections::HashSet;
use std::sync::{Mutex, OnceLock};

fn used_signatures() -> &'static Mutex<HashSet<String>> {
    static SET: OnceLock<Mutex<HashSet<String>>> = OnceLock::new();
    SET.get_or_init(|| Mutex::new(HashSet::new()))
}

#[derive(Default)]
pub struct VotingMutation;

#[Object]
impl VotingMutation {
    async fn submit_blind_vote(
        &self,
        _ctx: &Context<'_>,
        blind_signature: String,
        zk_snark_proof: String,
    ) -> Result<bool> {
        let proof_bytes = hex::decode(&zk_snark_proof)
            .map_err(|e| Error::new(format!("Invalid proof hex: {}", e)))?;
        let receipt: ZkReceipt = postcard::from_bytes(&proof_bytes)
            .map_err(|e| Error::new(format!("Invalid proof format: {}", e)))?;

        let transcript_hash = [0u8; 48];
        match ZkVerifier::verify(&receipt, &transcript_hash) {
            Ok(output) => {
                if !output.is_valid {
                    return Err(Error::new("ZK verification failed: receipt invalid"));
                }
            }
            Err(e) => return Err(Error::new(format!("ZK verification error: {}", e))),
        }

        let mut sigs = used_signatures().lock().unwrap();
        if sigs.contains(&blind_signature) {
            return Err(Error::new("Double voting detected: signature already used"));
        }
        sigs.insert(blind_signature.clone());

        tracing::info!("Blind vote verified and accepted.");
        Ok(true)
    }
}
