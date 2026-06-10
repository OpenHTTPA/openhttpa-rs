use std::sync::RwLock;

type FallbackHook = Box<dyn Fn(&str) + Send + Sync>;
static FALLBACK_HOOKS: RwLock<Vec<FallbackHook>> = RwLock::new(Vec::new());

/// Registers a callback hook that will be triggered whenever the TEE detection
/// falls back to a Mock provider or fails to find secure hardware.
///
/// This provides operational observability to detect misconfigured nodes
/// in production environments.
pub fn register_fallback_hook<F: Fn(&str) + Send + Sync + 'static>(hook: F) {
    if let Ok(mut hooks) = FALLBACK_HOOKS.write() {
        hooks.push(Box::new(hook));
    }
}

pub(crate) fn trigger_fallback_hook(reason: &str) {
    if let Ok(hooks) = FALLBACK_HOOKS.read() {
        for hook in hooks.iter() {
            hook(reason);
        }
    }
}
