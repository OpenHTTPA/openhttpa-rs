use crate::state::AppState;
use async_graphql::*;
use serde::{Deserialize, Serialize};

#[derive(SimpleObject, Serialize, Deserialize)]
pub struct PreKeyBundle {
    pub identity_key: String,
    pub signed_pre_key: String,
    pub pre_key_signature: String,
    pub one_time_pre_keys: Vec<String>,
}

#[derive(InputObject, Serialize, Deserialize)]
pub struct PreKeyBundleInput {
    pub identity_key: String,
    pub signed_pre_key: String,
    pub pre_key_signature: String,
    pub one_time_pre_keys: Vec<String>,
}

#[derive(Default)]
pub struct KeysQuery;

#[Object]
impl KeysQuery {
    async fn get_pre_keys(&self, ctx: &Context<'_>, device_id: String) -> Result<PreKeyBundle> {
        let app_state = ctx.data::<AppState>()?;
        if let Some(data) = app_state
            .storage
            .load(&device_id)
            .await
            .map_err(Error::new)?
        {
            let bundle: PreKeyBundle =
                serde_json::from_slice(&data).map_err(|e| Error::new(e.to_string()))?;
            Ok(bundle)
        } else {
            Ok(PreKeyBundle {
                identity_key: "mock_id".to_string(),
                signed_pre_key: "mock_signed".to_string(),
                pre_key_signature: "mock_sig".to_string(),
                one_time_pre_keys: vec!["mock_otpk".to_string()],
            })
        }
    }
}

#[derive(Default)]
pub struct KeysMutation;

#[Object]
impl KeysMutation {
    async fn upload_pre_keys(
        &self,
        ctx: &Context<'_>,
        device_id: String,
        keys: PreKeyBundleInput,
    ) -> Result<bool> {
        let app_state = ctx.data::<AppState>()?;
        let data = serde_json::to_vec(&keys).map_err(|e| Error::new(e.to_string()))?;
        app_state
            .storage
            .save(&device_id, &data)
            .await
            .map_err(Error::new)?;
        Ok(true)
    }
}
