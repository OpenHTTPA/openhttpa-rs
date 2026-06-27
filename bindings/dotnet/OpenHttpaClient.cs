using System;
using System.Runtime.InteropServices;
using System.Text.Json;
using System.Collections.Generic;

namespace OpenHttpa
{
    public class OpenHttpaClient : IDisposable
    {
        private const string LibName = "openhttpa_c";

        [DllImport(LibName, CallingConvention = CallingConvention.Cdecl)]
        private static extern IntPtr openhttpa_ctx_new();

        [DllImport(LibName, CallingConvention = CallingConvention.Cdecl)]
        private static extern void openhttpa_ctx_free(IntPtr ctx);

        [DllImport(LibName, CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi)]
        private static extern IntPtr openhttpa_confidential_chat(IntPtr ctx, string serverUri, string model, string messagesJson);

        [DllImport(LibName, CallingConvention = CallingConvention.Cdecl)]
        private static extern void openhttpa_free_string(IntPtr ptr);

        private IntPtr _ctx;

        public OpenHttpaClient()
        {
            _ctx = openhttpa_ctx_new();
            if (_ctx == IntPtr.Zero)
            {
                throw new Exception("Failed to initialize OpenHTTPA context");
            }
        }

        public string Chat(string endpoint, string model, string prompt)
        {
            var messages = new List<string[]> { new[] { "user", prompt } };
            string messagesJson = JsonSerializer.Serialize(messages);

            IntPtr resultPtr = openhttpa_confidential_chat(_ctx, endpoint, model, messagesJson);
            
            if (resultPtr == IntPtr.Zero)
            {
                throw new Exception("Confidential chat request failed");
            }

            string result = Marshal.PtrToStringAnsi(resultPtr) ?? string.Empty;
            openhttpa_free_string(resultPtr);

            return result;
        }

        public void Dispose()
        {
            if (_ctx != IntPtr.Zero)
            {
                openhttpa_ctx_free(_ctx);
                _ctx = IntPtr.Zero;
            }
        }
    }
}
