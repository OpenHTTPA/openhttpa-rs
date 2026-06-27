# OpenHTTPA .NET Bindings

These bindings allow .NET/C# applications to natively communicate with OpenHTTPA enclaves using P/Invoke connected to the C-ABI layer of the core Rust library.

## Project Structure

- `OpenHttpaClient.cs`: The core C# API wrapping the native `libopenhttpa_c` library.
- `tests/ClientTests.cs`: Comprehensive xUnit tests covering edge cases and unmanaged resource disposal.
- `examples/DotNetApp`: A full example application demonstrating how to initialize the TEE and send a confidential LLM prompt.

## Build Requirements

To build the native C library:

```bash
cargo build --release -p openhttpa-c
```

To build and run the .NET side, ensure you have the .NET 8.0+ SDK installed.

## Usage

See `examples/DotNetApp` for a complete example. In short:

```csharp
using (var client = new OpenHttpaClient("sgx"))
{
    string response = client.Chat("https://enclave:8443", "llama", "prompt");
}
```
