using System;
using OpenHttpa;

namespace DotNetApp
{
    class Program
    {
        static void Main(string[] args)
        {
            Console.WriteLine("Starting OpenHTTPA .NET Application...");

            try
            {
                // Initialize the OpenHTTPA Confidential Client specifying the backend hardware
                using (var client = new OpenHttpaClient("sgx"))
                {
                    Console.WriteLine("Hardware TEE Initialized Successfully.");

                    string endpoint = "https://confidential-llm.example.internal:8443";
                    string model = "llama-3-70b-instruct";
                    string prompt = "What are the latest enterprise features in OpenHTTPA?";

                    Console.WriteLine("Sending encrypted prompt to enclave...");
                    string response = client.Chat(endpoint, model, prompt);

                    Console.WriteLine($"Enclave responded: {response}");
                }
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine($"Fatal error during execution: {ex.Message}");
            }
        }
    }
}
