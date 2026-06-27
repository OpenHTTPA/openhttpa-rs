package org.openhttpa;

import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

public class ConfidentialClientTest {

    @Test
    public void testClientCreationAndDisposal() {
        // Edge case: Test that instantiating and immediately closing doesn't crash or leak memory
        try (ConfidentialClient client = new ConfidentialClient("sgx")) {
            assertNotNull(client, "Client should be initialized");
        } catch (Exception e) {
            fail("Exception thrown during lifecycle: " + e.getMessage());
        }
    }

    @Test
    public void testInvalidHardwareType() {
        // Edge case: Initializing with an unsupported TEE type
        Exception exception = assertThrows(RuntimeException.class, () -> {
            new ConfidentialClient("unsupported_tee");
        });
        
        // Error is propagated from the Rust JNI layer
        assertTrue(exception.getMessage().contains("Unsupported TEE") || exception.getMessage().contains("Failed"));
    }

    @Test
    public void testChatWithNullPrompt() {
        // Edge case: Ensuring null prompts from the Java side are handled safely
        try (ConfidentialClient client = new ConfidentialClient("sgx")) {
            Exception exception = assertThrows(NullPointerException.class, () -> {
                client.chat("http://localhost:8080", "llama-3", null);
            });
        } catch (Exception e) {
            fail("Failed to setup client");
        }
    }
}
