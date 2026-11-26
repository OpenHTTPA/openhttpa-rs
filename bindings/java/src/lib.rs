#![deny(clippy::unwrap_used)]
#![cfg_attr(test, allow(clippy::unwrap_used))]
use jni::JNIEnv;
use jni::objects::{JClass, JString};
use jni::sys::jstring;
use openhttpa_llm::{ChatMessage, ConfidentialLlmClient, Role};
use std::sync::OnceLock;
use tokio::runtime::Runtime;

static RUNTIME: OnceLock<Result<Runtime, String>> = OnceLock::new();

fn get_runtime() -> Result<&'static Runtime, String> {
    RUNTIME
        .get_or_init(|| Runtime::new().map_err(|e| format!("Failed to create tokio runtime: {e}")))
        .as_ref()
        .map_err(Clone::clone)
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_org_openhttpa_ConfidentialClient_chat<'local>(
    mut env: JNIEnv<'local>,
    _class: JClass<'local>,
    endpoint: JString<'local>,
    model: JString<'local>,
    prompt: JString<'local>,
) -> jstring {
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let result: Result<String, String> = (|| {
            let endpoint: String = env
                .get_string(&endpoint)
                .map_err(|e| format!("Invalid endpoint string: {e}"))?
                .into();
            let model: String = env
                .get_string(&model)
                .map_err(|e| format!("Invalid model string: {e}"))?
                .into();
            let prompt: String = env
                .get_string(&prompt)
                .map_err(|e| format!("Invalid prompt string: {e}"))?
                .into();

            let uri = endpoint
                .parse()
                .map_err(|e| format!("Invalid endpoint URI: {e}"))?;
            let rt = get_runtime()?;
            rt.block_on(async {
                let client = ConfidentialLlmClient::builder()
                    .server_uri(uri)
                    .model(&model)
                    .build()
                    .await
                    .map_err(|e| e.to_string())?;

                let messages = vec![ChatMessage {
                    role: Role::User,
                    content: prompt,
                }];

                client.chat(&messages).await.map_err(|e| e.to_string())
            })
        })();

        match result {
            Ok(reply) => match env.new_string(reply) {
                Ok(output) => output.into_raw(),
                Err(e) => {
                    let _ = env.throw_new(
                        "java/lang/RuntimeException",
                        format!("Failed to create Java string: {e}"),
                    );
                    std::ptr::null_mut()
                }
            },
            Err(err) => {
                let _ = env.throw_new("java/lang/RuntimeException", err);
                std::ptr::null_mut()
            }
        }
    }))
    .unwrap_or(std::ptr::null_mut())
}
