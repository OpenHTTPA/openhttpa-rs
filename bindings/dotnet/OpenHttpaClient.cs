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

        [DllImport(LibName, CallingConvention = CallingConvention.Cdecl)]
        private static extern IntPtr openhttpa_confidential_chat(
            IntPtr ctx,
            [MarshalAs(UnmanagedType.LPUTF8Str)] string serverUri,
            [MarshalAs(UnmanagedType.LPUTF8Str)] string model,
            [MarshalAs(UnmanagedType.LPUTF8Str)] string messagesJson);

        [DllImport(LibName, CallingConvention = CallingConvention.Cdecl)]
        private static extern void openhttpa_free_string(IntPtr ptr);

        private IntPtr _ctx;
        private bool _disposed;

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
            if (_disposed || _ctx == IntPtr.Zero)
            {
                throw new ObjectDisposedException(nameof(OpenHttpaClient));
            }

            var messages = new List<string[]> { new[] { "user", prompt } };
            string messagesJson = JsonSerializer.Serialize(messages);

            IntPtr resultPtr = openhttpa_confidential_chat(_ctx, endpoint, model, messagesJson);
            if (resultPtr == IntPtr.Zero)
            {
                throw new Exception("Confidential chat request failed");
            }

            try
            {
                return Marshal.PtrToStringUTF8(resultPtr) ?? string.Empty;
            }
            finally
            {
                openhttpa_free_string(resultPtr);
            }
        }

        ~OpenHttpaClient()
        {
            Dispose(false);
        }

        public void Dispose()
        {
            Dispose(true);
            GC.SuppressFinalize(this);
        }

        protected virtual void Dispose(bool disposing)
        {
            if (!_disposed && _ctx != IntPtr.Zero)
            {
                openhttpa_ctx_free(_ctx);
                _ctx = IntPtr.Zero;
            }
            _disposed = true;
        }
    }
}
