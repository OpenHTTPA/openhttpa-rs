package org.openhttpa;

public class ConfidentialClient {
    static {
        System.loadLibrary("openhttpa_java");
    }

    /**
     * Executes a confidential chat request over OpenHTTPA.
     *
     * @param endpoint The URL of the OpenHTTPA server (e.g., "http://127.0.0.1:8080").
     * @param model    The model to use (e.g., "llama3").
     * @param prompt   The user prompt to send to the model.
     * @return The response from the model.
     * @throws RuntimeException if the attestation or execution fails.
     */
    public static native String chat(String endpoint, String model, String prompt);
}
