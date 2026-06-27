package org.example;

import org.openhttpa.ConfidentialClient;

public class Main {
    public static void main(String[] args) {
        System.out.println("Starting OpenHTTPA Java Application...");

        // Initialize the OpenHTTPA Confidential Client specifying the backend hardware (e.g., SGX)
        try (ConfidentialClient client = new ConfidentialClient("sgx")) {
            System.out.println("Hardware TEE Initialized Successfully.");

            String endpoint = "https://confidential-llm.example.internal:8443";
            String model = "llama-3-70b-instruct";
            String prompt = "What are the latest enterprise features in OpenHTTPA?";

            System.out.println("Sending encrypted prompt to enclave...");
            String response = client.chat(endpoint, model, prompt);

            System.out.println("Enclave responded: " + response);
        } catch (Exception e) {
            System.err.println("Fatal error during execution: " + e.getMessage());
        }
    }
}
