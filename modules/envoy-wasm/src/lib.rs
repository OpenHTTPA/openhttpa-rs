use log::info;
use proxy_wasm::traits::*;
use proxy_wasm::types::*;

proxy_wasm::main! {{
    proxy_wasm::set_log_level(LogLevel::Trace);
    proxy_wasm::set_http_context(|context_id, _| -> Box<dyn HttpContext> {
        Box::new(OpenHttpaFilter { context_id })
    });
}}

struct OpenHttpaFilter {
    context_id: u32,
}

impl Context for OpenHttpaFilter {}

impl HttpContext for OpenHttpaFilter {
    fn on_http_request_headers(&mut self, _: usize, _: bool) -> Action {
        if let Some(attest_version) = self.get_http_request_header("Attest-Versions") {
            info!(
                "[{}] Detected OpenHTTPA request with Attest-Versions: {}",
                self.context_id, attest_version
            );

            if process_openhttpa_headers(&attest_version) {
                self.set_http_request_header("X-OpenHTTPA-Proxied", Some("true"));
            }
        }
        Action::Continue
    }

    fn on_http_response_headers(&mut self, _: usize, _: bool) -> Action {
        Action::Continue
    }
}

fn process_openhttpa_headers(versions: &str) -> bool {
    versions.contains("1.0")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_process_openhttpa_headers() {
        assert!(process_openhttpa_headers("1.0, 1.1"));
        assert!(!process_openhttpa_headers("2.0"));

        // Edge cases
        assert!(!process_openhttpa_headers(""));
        assert!(!process_openhttpa_headers("   "));
        // Very large or weird payload
        let large_payload = "1.0".repeat(1000);
        assert!(process_openhttpa_headers(&large_payload));
    }
}
