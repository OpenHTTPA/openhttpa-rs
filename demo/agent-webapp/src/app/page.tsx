'use client';

import { useState } from 'react';

export default function Home() {
  const [agentPayload, setAgentPayload] = useState('');
  const [e2ePayload, setE2ePayload] = useState('');
  const [bypass, setBypass] = useState(false);
  const [confidence, setConfidence] = useState('0.9');
  const [policyId, setPolicyId] = useState('');
  const [clientPosture, setClientPosture] = useState('OneDirectional');

  const [logs, setLogs] = useState<string[]>([]);
  const [inbox, setInbox] = useState<{ id: string; payload: string; intent: string }[]>([]);
  const [loading, setLoading] = useState(false);

  const [isTeeVerified, setIsTeeVerified] = useState(false);
  const [teeQuote, setTeeQuote] = useState<any>(null);

  const [clarification, setClarification] = useState<{
    messageId: string;
    questions: string[];
  } | null>(null);
  const [answer, setAnswer] = useState('');

  const addLog = (msg: string) => {
    setLogs((prev) => [`[${new Date().toLocaleTimeString()}] ${msg}`, ...prev]);
  };

  const handleVerifyTee = async () => {
    setLoading(true);
    addLog(`Requesting TDX Attestation Quote from Agent Server...`);
    const nonce = Math.random().toString(36).substring(2);

    try {
      const response = await fetch('/api/graphql', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          query: `
            query GetAttestation($nonce: String!) {
              getAgentAttestation(nonce: $nonce) {
                quoteType
                rawBase64
                quddBase64
              }
            }
          `,
          variables: { nonce },
        }),
      });

      const result = await response.json();
      const quote = result.data?.getAgentAttestation;

      if (quote) {
        setTeeQuote(quote);
        // Simulate cryptographic verification
        addLog(
          `Received ${quote.quoteType.toUpperCase()} Quote. Simulating cryptographic verification...`,
        );
        setTimeout(() => {
          setIsTeeVerified(true);
          addLog(`Success! Agent Server TEE identity verified against Intel PCK.`);
          setLoading(false);
        }, 1000);
      } else {
        addLog(`Error: Failed to fetch attestation quote.`);
        setLoading(false);
      }
    } catch (err: any) {
      addLog(`Error: ${err.message}`);
      setLoading(false);
    }
  };

  const handleDispatch = async () => {
    if (!agentPayload.trim() && !e2ePayload.trim()) return;
    setLoading(true);
    addLog(`Dispatching intent (Bypass: ${bypass})...`);

    try {
      const response = await fetch('/api/graphql', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: 'MockVerifiedDid',
          'x-simulate-client-posture': clientPosture,
        },
        body: JSON.stringify({
          query: `
            mutation SendMessage($msg: SealedSenderMessageInput!) {
              sendSealedMessage(message: $msg) {
                ... on MessageDispatchSuccess {
                  messageId
                  dispatched
                }
                ... on ClarificationPrompt {
                  messageId
                  originalIntent
                  clarifyingQuestions
                }
              }
            }
          `,
          variables: {
            msg: {
              recipientDeviceId: 'target_agent_xyz',
              agentUnsealablePayload: agentPayload,
              e2eEncryptedPayload: e2ePayload,
              aiqlPolicy: {
                bypassClarification: bypass,
                confidenceThreshold: parseFloat(confidence),
                policyId: policyId || null,
              },
            },
          },
        }),
      });

      const result = await response.json();
      const data = result.data?.sendSealedMessage;

      if (data?.dispatched) {
        addLog(`Success! Intent dispatched immediately. ID: ${data.messageId}`);
        setInbox((prev) => [
          { id: data.messageId, payload: e2ePayload, intent: agentPayload },
          ...prev,
        ]);
        setAgentPayload('');
        setE2ePayload('');
      } else if (data?.clarifyingQuestions) {
        addLog(`Intent flagged as ambiguous. Awaiting clarification...`);
        setClarification({
          messageId: data.messageId,
          questions: data.clarifyingQuestions,
        });
      } else {
        addLog(`Error: Unexpected response format.`);
      }
    } catch (err: any) {
      addLog(`Error: ${err.message}`);
    } finally {
      setLoading(false);
    }
  };

  const handleConfirm = async () => {
    if (!answer.trim() || !clarification) return;
    setLoading(true);
    addLog(`Sending clarification response...`);

    try {
      const response = await fetch('/api/graphql', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: 'MockVerifiedDid',
          'x-simulate-client-posture': clientPosture,
        },
        body: JSON.stringify({
          query: `
            mutation ConfirmMessage($id: String!, $ans: String!, $msg: SealedSenderMessageInput!) {
              confirmMessageIntent(messageId: $id, clarifiedPayload: $ans, message: $msg) {
                ... on MessageDispatchSuccess {
                  messageId
                  dispatched
                }
                ... on ClarificationPrompt {
                  messageId
                  clarifyingQuestions
                }
              }
            }
          `,
          variables: {
            id: clarification.messageId,
            ans: answer,
            msg: {
              recipientDeviceId: 'target_agent_xyz',
              agentUnsealablePayload: agentPayload,
              e2eEncryptedPayload: e2ePayload,
              aiqlPolicy: {
                bypassClarification: false, // Never bypass during clarification
                confidenceThreshold: parseFloat(confidence),
                policyId: policyId || null,
              },
            },
          },
        }),
      });

      const result = await response.json();
      const data = result.data?.confirmMessageIntent;

      if (data?.dispatched) {
        addLog(`Clarification accepted! AIQL Intent dispatched. ID: ${data.messageId}`);
        setInbox((prev) => [{ id: data.messageId, payload: e2ePayload, intent: answer }, ...prev]);
        setClarification(null);
        setAnswer('');
        setAgentPayload('');
        setE2ePayload('');
      } else if (data?.clarifyingQuestions) {
        addLog(`Still ambiguous! Server asked: ${data.clarifyingQuestions[0]}`);
      }
    } catch (err: any) {
      addLog(`Error: ${err.message}`);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="flex flex-col items-center justify-center py-12 px-4 sm:px-6 lg:px-8">
      <div className="w-full max-w-3xl space-y-8">
        <div className="text-center">
          <h1 className="font-outfit text-5xl font-extrabold bg-gradient-to-r from-purple-500 to-indigo-500 bg-clip-text text-transparent mb-2">
            AI Agent Server
          </h1>
          <p className="text-slate-300 text-lg">Decentralized AIQL Intelligence</p>
        </div>

        <main className="glass-panel p-6 space-y-6">
          <section className="space-y-4">
            <h2 className="font-outfit text-2xl font-bold">AIQL Policy Configuration</h2>
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-4 bg-slate-900/50 p-4 rounded-xl border border-white/5">
              <label className="flex items-center space-x-3 cursor-pointer">
                <input
                  type="checkbox"
                  checked={bypass}
                  onChange={(e) => setBypass(e.target.checked)}
                  className="w-5 h-5 rounded border-slate-600 text-indigo-600 focus:ring-indigo-500 bg-slate-800"
                />
                <span className="text-slate-200">Bypass Clarification</span>
              </label>

              <div className="flex items-center space-x-3">
                <span className="text-slate-200">Confidence:</span>
                <input
                  type="number"
                  step="0.1"
                  min="0"
                  max="1"
                  value={confidence}
                  onChange={(e) => setConfidence(e.target.value)}
                  className="w-20 bg-slate-800 border border-slate-600 rounded px-2 py-1 focus:ring-indigo-500 focus:border-indigo-500"
                />
              </div>

              <div className="flex items-center space-x-3 sm:col-span-2">
                <span className="text-slate-200">Policy ID:</span>
                <input
                  type="text"
                  placeholder="e.g. strict-financial-01"
                  value={policyId}
                  onChange={(e) => setPolicyId(e.target.value)}
                  className="flex-1 bg-slate-800 border border-slate-600 rounded px-3 py-1 focus:ring-indigo-500 focus:border-indigo-500"
                />
              </div>
            </div>
          </section>

          <section className="space-y-4">
            <h2 className="font-outfit text-2xl font-bold flex items-center justify-between">
              <span>Agent Server TEE Verification</span>
              {isTeeVerified && (
                <span className="text-sm px-3 py-1 bg-emerald-500/20 text-emerald-400 rounded-full border border-emerald-500/30">
                  Verified TDX TEE
                </span>
              )}
            </h2>
            {!isTeeVerified ? (
              <div className="bg-slate-900/50 p-6 rounded-xl border border-rose-500/30 text-center space-y-4">
                <p className="text-slate-300">
                  Before transmitting highly sensitive AIQL intent or E2E encrypted payloads, you
                  must verify the cryptographic identity of the remote Agent Server.
                </p>
                <button
                  onClick={handleVerifyTee}
                  disabled={loading}
                  className="px-6 py-3 bg-rose-600 hover:bg-rose-500 active:bg-rose-700 disabled:opacity-50 rounded-lg font-outfit font-semibold shadow-lg shadow-rose-500/30 transition-all"
                >
                  Request & Verify TDX Quote
                </button>
              </div>
            ) : (
              <div className="bg-slate-900/50 p-4 rounded-xl border border-emerald-500/30 space-y-2">
                <p className="text-sm text-slate-300">
                  The remote Agent Server is running inside a verified Intel TDX environment.
                </p>
                <div className="bg-slate-950 p-3 rounded font-mono text-xs text-emerald-400 overflow-hidden text-ellipsis whitespace-nowrap">
                  QUDD: {teeQuote?.quddBase64}
                </div>
              </div>
            )}
          </section>

          <section className="space-y-4">
            <h2 className="font-outfit text-2xl font-bold">Client Security Posture Simulation</h2>
            <div className="bg-slate-900/50 p-4 rounded-xl border border-white/5">
              <label className="block text-sm font-medium text-slate-300 mb-2">
                Simulate Client Environment:
              </label>
              <select
                value={clientPosture}
                onChange={(e) => setClientPosture(e.target.value)}
                className="w-full bg-slate-800 border border-slate-600 rounded-lg px-4 py-2 text-slate-200 focus:ring-2 focus:ring-indigo-500"
              >
                <option value="OneDirectional">Non-TEE Environment (One-Directional)</option>
                <option value="SimulatedTee">Mock / Simulated TEE Environment</option>
                <option value="MutualTee">Genuine TEE Enclave (Mutual Attestation)</option>
              </select>
            </div>
          </section>

          <section className="space-y-4">
            <h2 className="font-outfit text-2xl font-bold">Send a Sealed Intent</h2>
            <div className="space-y-3">
              <div>
                <label className="block text-sm font-medium text-slate-300 mb-1">
                  Agent Unsealable Payload (TEE AIQL Evaluation)
                </label>
                <textarea
                  value={agentPayload}
                  onChange={(e) => setAgentPayload(e.target.value)}
                  placeholder="E.g., I want to transfer 50 tokens to agent 0x... (Can be evaluated by TEE Agent Server)"
                  rows={3}
                  className="w-full bg-slate-900/80 border border-slate-700 rounded-xl p-4 text-slate-100 placeholder-slate-500 focus:ring-2 focus:ring-indigo-500 focus:border-transparent transition-all resize-none"
                />
              </div>
              <div>
                <label className="block text-sm font-medium text-slate-300 mb-1">
                  End-to-End Encrypted Payload (Recipient Only)
                </label>
                <textarea
                  value={e2ePayload}
                  onChange={(e) => setE2ePayload(e.target.value)}
                  placeholder="E.g., Secure keys or private memo... (Opaque to the Agent Server)"
                  rows={2}
                  className="w-full bg-slate-900/80 border border-slate-700 rounded-xl p-4 text-slate-100 placeholder-slate-500 focus:ring-2 focus:ring-indigo-500 focus:border-transparent transition-all resize-none"
                />
              </div>
            </div>
            <button
              onClick={handleDispatch}
              disabled={loading || !isTeeVerified || (!agentPayload.trim() && !e2ePayload.trim())}
              className="w-full sm:w-auto px-6 py-3 bg-indigo-600 hover:bg-indigo-500 active:bg-indigo-700 disabled:opacity-50 disabled:cursor-not-allowed rounded-lg font-outfit font-semibold shadow-lg shadow-indigo-500/30 transition-all"
            >
              Dispatch Intent
            </button>
          </section>

          {clarification && (
            <section className="glass-panel p-6 bg-slate-900/90 border-amber-500/30 shadow-2xl animate-in slide-in-from-bottom-4">
              <h2 className="font-outfit text-2xl font-bold text-amber-500 mb-4">
                Intent Ambiguous!
              </h2>
              <div className="mb-4 text-slate-300">
                <strong>Server asked:</strong>
                <ul className="list-disc pl-5 mt-2 space-y-1">
                  {clarification.questions.map((q, i) => (
                    <li key={i}>{q}</li>
                  ))}
                </ul>
              </div>
              <input
                type="text"
                value={answer}
                onChange={(e) => setAnswer(e.target.value)}
                placeholder="Provide clarity here..."
                className="w-full bg-slate-800 border border-slate-600 rounded-lg px-4 py-3 mb-4 focus:ring-2 focus:ring-amber-500 focus:border-transparent"
              />
              <button
                onClick={handleConfirm}
                disabled={loading || !answer.trim()}
                className="w-full sm:w-auto px-6 py-3 bg-emerald-600 hover:bg-emerald-500 active:bg-emerald-700 disabled:opacity-50 rounded-lg font-outfit font-semibold shadow-lg shadow-emerald-500/30 transition-all"
              >
                Confirm Intent
              </button>
            </section>
          )}

          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
            <section className="space-y-4">
              <h2 className="font-outfit text-2xl font-bold border-b border-slate-700 pb-2">
                Sender Transaction Log
              </h2>
              <ul className="space-y-2 max-h-64 overflow-y-auto pr-2 custom-scrollbar">
                {logs.map((log, i) => (
                  <li
                    key={i}
                    className="text-sm text-slate-400 font-mono border-b border-slate-800 pb-2"
                  >
                    {log}
                  </li>
                ))}
                {logs.length === 0 && (
                  <li className="text-sm text-slate-600 italic">No transactions yet.</li>
                )}
              </ul>
            </section>

            <section className="space-y-4">
              <h2 className="font-outfit text-2xl font-bold border-b border-slate-700 pb-2 text-emerald-400">
                Receiver Inbox
              </h2>
              <ul className="space-y-4 max-h-64 overflow-y-auto pr-2 custom-scrollbar">
                {inbox.map((msg, i) => (
                  <li
                    key={i}
                    className="p-4 bg-slate-900/50 rounded-xl border border-emerald-500/20 shadow-inner"
                  >
                    <p className="text-xs text-slate-500 mb-2 font-mono">Msg ID: {msg.id}</p>
                    <div className="space-y-2">
                      <div>
                        <span className="text-xs font-semibold text-emerald-500 uppercase tracking-wider">
                          Resolved AIQL Intent
                        </span>
                        <p className="text-sm text-slate-300 bg-slate-800/50 p-2 rounded mt-1">
                          {msg.intent}
                        </p>
                      </div>
                      <div>
                        <span className="text-xs font-semibold text-purple-400 uppercase tracking-wider">
                          Decrypted E2E Payload
                        </span>
                        <p className="text-sm text-slate-200 bg-slate-800/80 p-2 rounded mt-1 border-l-2 border-purple-500">
                          {msg.payload || 'No E2E Payload'}
                        </p>
                      </div>
                    </div>
                  </li>
                ))}
                {inbox.length === 0 && (
                  <li className="text-sm text-slate-600 italic">Awaiting incoming messages...</li>
                )}
              </ul>
            </section>
          </div>
        </main>
      </div>
    </div>
  );
}
