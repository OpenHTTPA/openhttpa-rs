use crate::agent::aiql_pipeline::{AiqlPipeline, ClarificationPrompt, IntentStatus};
use async_graphql::*;
use futures::stream::Stream;

#[derive(SimpleObject, Clone)]
pub struct AiqlPolicyConfig {
    pub bypass_clarification: Option<bool>,
    pub confidence_threshold: Option<f64>,
    pub policy_id: Option<String>,
}

#[derive(InputObject, Clone)]
pub struct AiqlPolicyConfigInput {
    pub bypass_clarification: Option<bool>,
    pub confidence_threshold: Option<f64>,
    pub policy_id: Option<String>,
}

#[derive(SimpleObject)]
pub struct SealedSenderMessage {
    pub recipient_device_id: String,
    pub agent_unsealable_payload: String,
    #[graphql(name = "e2eEncryptedPayload")]
    pub e2e_encrypted_payload: String,
    pub aiql_policy: Option<AiqlPolicyConfig>,
    pub aiql_intent: Option<String>,
}

#[derive(InputObject)]
pub struct SealedSenderMessageInput {
    pub recipient_device_id: String,
    pub agent_unsealable_payload: String,
    #[graphql(name = "e2eEncryptedPayload")]
    pub e2e_encrypted_payload: String,
    pub aiql_policy: Option<AiqlPolicyConfigInput>,
    pub aiql_intent: Option<String>,
}

#[derive(SimpleObject)]
pub struct MessageDispatchSuccess {
    pub message_id: String,
    pub dispatched: bool,
}

#[derive(Union)]
pub enum SendMessageResult {
    Success(MessageDispatchSuccess),
    NeedsClarification(ClarificationPrompt),
}

#[derive(Default)]
pub struct MessagesQuery;

#[Object]
impl MessagesQuery {
    async fn check_messages(&self, _ctx: &Context<'_>) -> Result<bool> {
        Ok(true)
    }
}

#[derive(Default)]
pub struct MessagesMutation;

#[Object]
impl MessagesMutation {
    async fn send_sealed_message(
        &self,
        ctx: &Context<'_>,
        message: SealedSenderMessageInput,
    ) -> Result<SendMessageResult> {
        let posture = ctx.data_opt::<openhttpa_proto::ClientSecurityPosture>();
        tracing::info!(
            "Received send_sealed_message intent from client with posture: {:?}",
            posture
        );

        let message_id = uuid::Uuid::new_v4().to_string();

        match AiqlPipeline::evaluate_intent(
            &message_id,
            &message.agent_unsealable_payload,
            &message.aiql_policy,
        )
        .await
        {
            IntentStatus::Ambiguous(prompt) => {
                // Return the prompt to the sender so they can clarify
                Ok(SendMessageResult::NeedsClarification(prompt))
            }
            IntentStatus::Clear(intent) => {
                // Proceed with dispatching the message, now with clear AIQL attached
                // TODO: Route message to recipient
                let _final_message = SealedSenderMessage {
                    aiql_intent: Some(intent),
                    recipient_device_id: message.recipient_device_id.clone(),
                    agent_unsealable_payload: message.agent_unsealable_payload.clone(),
                    e2e_encrypted_payload: message.e2e_encrypted_payload.clone(),
                    aiql_policy: message.aiql_policy.as_ref().map(|p| AiqlPolicyConfig {
                        bypass_clarification: p.bypass_clarification,
                        confidence_threshold: p.confidence_threshold,
                        policy_id: p.policy_id.clone(),
                    }),
                };

                Ok(SendMessageResult::Success(MessageDispatchSuccess {
                    message_id,
                    dispatched: true,
                }))
            }
        }
    }

    async fn confirm_message_intent(
        &self,
        _ctx: &Context<'_>,
        _message_id: String,
        clarified_payload: String,
        message: SealedSenderMessageInput,
    ) -> Result<SendMessageResult> {
        // Evaluate the clarified payload (never bypasses when clarifying)
        match AiqlPipeline::evaluate_intent(&_message_id, &clarified_payload, &None).await {
            IntentStatus::Ambiguous(prompt) => Ok(SendMessageResult::NeedsClarification(prompt)),
            IntentStatus::Clear(aiql_intent) => {
                let _final_message = SealedSenderMessage {
                    aiql_intent: Some(aiql_intent),
                    recipient_device_id: message.recipient_device_id.clone(),
                    agent_unsealable_payload: clarified_payload.clone(), // Store clarified payload as the agent-unsealable part for routing
                    e2e_encrypted_payload: message.e2e_encrypted_payload.clone(),
                    aiql_policy: message.aiql_policy.as_ref().map(|p| AiqlPolicyConfig {
                        bypass_clarification: p.bypass_clarification,
                        confidence_threshold: p.confidence_threshold,
                        policy_id: p.policy_id.clone(),
                    }),
                };

                Ok(SendMessageResult::Success(MessageDispatchSuccess {
                    message_id: _message_id,
                    dispatched: true,
                }))
            }
        }
    }
}

#[derive(Default)]
pub struct MessagesSubscription;

#[Subscription]
impl MessagesSubscription {
    async fn message_stream(&self, _ctx: &Context<'_>) -> impl Stream<Item = SealedSenderMessage> {
        futures::stream::empty()
    }
}
