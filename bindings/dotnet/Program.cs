using System;
using OpenHttpa;

class Program
{
    static void Main(string[] args)
    {
        Console.WriteLine("Testing C# bindings for OpenHTTPA");
        try
        {
            using (var client = new OpenHttpaClient("sgx"))
            {
                Console.WriteLine("Successfully created ConfidentialClient.");
            }
        }
        catch (Exception e)
        {
            Console.WriteLine($"Error: {e.Message}");
        }
    }
}
