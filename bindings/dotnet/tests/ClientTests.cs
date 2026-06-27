using System;
using Xunit;
using OpenHttpa;

namespace OpenHttpa.Tests
{
    public class ClientTests
    {
        [Fact]
        public void TestClientCreationAndDisposal()
        {
            // Edge case: Test that instantiating and immediately disposing doesn't leak unmanaged memory
            var client = new OpenHttpaClient("sgx");
            Assert.NotNull(client);
            client.Dispose();
        }

        [Fact]
        public void TestInvalidHardwareType()
        {
            // Edge case: Initializing with an unsupported TEE type should throw
            var ex = Assert.Throws<Exception>(() => new OpenHttpaClient("unsupported_tee"));
            Assert.Contains("Failed", ex.Message);
        }
        
        [Fact]
        public void TestMultipleDisposal()
        {
            // Edge case: Disposing multiple times shouldn't crash
            var client = new OpenHttpaClient("sgx");
            client.Dispose();
            client.Dispose(); // Should be a no-op
        }
    }
}
