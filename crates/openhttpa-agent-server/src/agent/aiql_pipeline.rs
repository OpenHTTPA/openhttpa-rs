use async_graphql::*;
use openhttpa_aiql::parser::AiqlParser;
use openhttpa_llm::enclave_inference::EnclaveInferenceEngine;

#[derive(SimpleObject, Clone)]
pub struct ClarificationPrompt {
    pub message_id: String,
    pub original_intent: String,
    pub clarifying_questions: Vec<String>,
}

pub enum IntentStatus {
    Clear(String),
    Ambiguous(ClarificationPrompt),
}

/// Pipeline to intercept raw messages and translate/verify AIQL intentions
pub struct AiqlPipeline;

impl AiqlPipeline {
    /// Evaluates raw message payload. If the intention is ambiguous, it returns
    /// a clarification prompt. Otherwise, it returns the confirmed AIQL string.
    pub async fn evaluate_intent(
        message_id: &str,
        agent_unsealable_payload: &str,
        policy: &Option<crate::graphql::messages::AiqlPolicyConfigInput>,
    ) -> IntentStatus {
        if policy
            .as_ref()
            .is_some_and(|p| p.bypass_clarification.unwrap_or(false))
        {
            return IntentStatus::Clear(format!(
                "AIQL: DeterministicPolicy[{}]",
                agent_unsealable_payload
            ));
        }

        if agent_unsealable_payload.trim().starts_with('{')
            && let Err(e) = AiqlParser::parse_json(agent_unsealable_payload)
        {
            return IntentStatus::Ambiguous(ClarificationPrompt {
                message_id: message_id.to_string(),
                original_intent: agent_unsealable_payload.to_string(),
                clarifying_questions: vec![format!("Invalid AIQL JSON: {}", e)],
            });
        }

        let engine = EnclaveInferenceEngine::new().unwrap();
        let llm_result = engine
            .run_inference(agent_unsealable_payload)
            .unwrap_or_default();

        let threshold = policy
            .as_ref()
            .and_then(|p| p.confidence_threshold)
            .unwrap_or(0.8);
        let confidence = if agent_unsealable_payload.contains("ambiguous") {
            0.5
        } else {
            0.9
        };

        if confidence < threshold {
            IntentStatus::Ambiguous(ClarificationPrompt {
                message_id: message_id.to_string(),
                original_intent: agent_unsealable_payload.to_string(),
                clarifying_questions: vec![
                    "Could you specify the exact amount?".to_string(),
                    "Who is the intended final recipient?".to_string(),
                ],
            })
        } else {
            IntentStatus::Clear(format!(
                "AIQL: Translated[{}] via LLM[{}]",
                agent_unsealable_payload, llm_result
            ))
        }
    }
}
