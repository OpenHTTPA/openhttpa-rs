# OpenHTTPA Java Bindings

These bindings allow Java applications to natively communicate with OpenHTTPA enclaves using JNI (Java Native Interface) connected to the core Rust library.

## Project Structure

- `src/main/java/org/openhttpa`: The core Java API (`ConfidentialClient.java`)
- `src/test/java/org/openhttpa`: Comprehensive JUnit tests covering edge cases and lifecycle management.
- `examples/JavaApp`: A full example application demonstrating how to initialize the TEE and send a confidential LLM prompt.

## Build Requirements

To build the native JNI library:

```bash
cargo build --release -p openhttpa-java
```

To build and run the Java side, ensure you have JDK 17+ installed.

## Usage

See `examples/JavaApp` for a complete example. In short:

```java
try (ConfidentialClient client = new ConfidentialClient("sgx")) {
    String response = client.chat("https://enclave:8443", "llama", "prompt");
}
```
