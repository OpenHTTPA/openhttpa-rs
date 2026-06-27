use jni::JNIEnv;
use jni::objects::{JClass, JString};
use jni::sys::jstring;
use openhttpa_llm::{ChatMessage, ConfidentialLlmClient, Role};
use std::sync::OnceLock;
use tokio::runtime::Runtime;

static RUNTIME: OnceLock<Runtime> = OnceLock::new();

fn get_runtime() -> &'static Runtime {
    RUNTIME.get_or_init(|| Runtime::new().unwrap())
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_org_openhttpa_ConfidentialClient_chat<'local>(
    mut env: JNIEnv<'local>,
    _class: JClass<'local>,
    endpoint: JString<'local>,
    model: JString<'local>,
    prompt: JString<'local>,
) -> jstring {
    let endpoint: String = env.get_string(&endpoint).unwrap().into();
    let _model: String = env.get_string(&model).unwrap().into();
    let prompt: String = env.get_string(&prompt).unwrap().into();

    let rt = get_runtime();
    let result = rt.block_on(async {
        let client = ConfidentialLlmClient::builder()
            .await
            .server_uri(endpoint.parse().unwrap())
            .build()
            .await
            .map_err(|e| e.to_string())?;

        let messages = vec![ChatMessage {
            role: Role::User,
            content: prompt,
        }];

        client.chat(&messages).await.map_err(|e| e.to_string())
    });

    match result {
        Ok(reply) => {
            let output = env.new_string(reply).unwrap();
            output.into_raw()
        }
        Err(err) => {
            env.throw_new("java/lang/RuntimeException", err).unwrap();
            std::ptr::null_mut()
        }
    }
}
