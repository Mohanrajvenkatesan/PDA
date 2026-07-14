import React, { useState, useEffect, useRef } from "react";
import { Play, Pause, SkipForward, RotateCcw, ShieldAlert, ShieldCheck, Lock, Loader2 } from "lucide-react";

const SAMPLES = {
  "Valid nested JSON": JSON.stringify({ order: { id: 1, items: [{ sku: "A1" }, { sku: "B2", meta: { qty: 3 } }] } }, null, 0),
  "Unbalanced JSON": '{"order": {"id": 1, "items": [1, 2, 3]}',
  "Prototype pollution": '{"__proto__": {"isAdmin": true}}',
  "Valid XML": '<order id="1"><items><item sku="A1"/><item sku="B2"><meta qty="3"/></item></items></order>',
  "Mismatched XML tags": "<order><items><item></order></items>",
  "Nesting-bomb": "[".repeat(14) + "]".repeat(14),
};

// Both calls hit the real Express backend. In dev, vite.config.js proxies
// /api/* to http://localhost:4000, so no hardcoded host is needed here.
async function encryptPayload(plaintext) {
  const res = await fetch("/api/encrypt", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ plaintext }),
  });
  if (!res.ok) throw new Error(`encrypt failed: ${res.status}`);
  return res.json();
}

async function validateEnvelope(envelope) {
  const res = await fetch("/api/validate", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(envelope),
  });
  // 200 = valid, 422 = structurally rejected — both are real responses to render
  return res.json();
}

export default function PDAVisualizer() {
  const [payload, setPayload] = useState(SAMPLES["Valid nested JSON"]);
  const [envelope, setEnvelope] = useState(null);
  const [result, setResult] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);
  const [stepIdx, setStepIdx] = useState(0);
  const [playing, setPlaying] = useState(false);
  const timerRef = useRef(null);
  const debounceRef = useRef(null);

  // Re-run encrypt -> validate against the real backend whenever the
  // payload changes, debounced so we don't fire a request per keystroke.
  useEffect(() => {
    setStepIdx(0);
    setPlaying(false);
    setError(null);
    clearTimeout(debounceRef.current);
    debounceRef.current = setTimeout(async () => {
      setLoading(true);
      try {
        const env = await encryptPayload(payload);
        setEnvelope(env);
        const res = await validateEnvelope(env);
        setResult(res);
      } catch (e) {
        setError(e.message || "Request to backend failed");
        setResult(null);
      } finally {
        setLoading(false);
      }
    }, 350);
    return () => clearTimeout(debounceRef.current);
  }, [payload]);

  const trace = result?.trace || [];
  const current = trace[Math.min(stepIdx, trace.length - 1)] || { stack: [], action: "NOOP", depth: 0 };

  useEffect(() => {
    if (!playing) return;
    if (stepIdx >= trace.length - 1) { setPlaying(false); return; }
    timerRef.current = setTimeout(() => setStepIdx((s) => s + 1), 260);
    return () => clearTimeout(timerRef.current);
  }, [playing, stepIdx, trace.length]);

  const isViolationStep = current.action === "ERROR" || current.action === "REJECT";

  return (
    <div className="w-full max-w-4xl mx-auto bg-slate-950 text-slate-200 rounded-xl border border-slate-800 p-5 font-sans">
      <div className="flex items-center justify-between mb-4">
        <div className="flex items-center gap-2">
          <Lock size={16} className="text-cyan-400" />
          <h2 className="text-sm font-medium tracking-wide text-slate-300">PDA payload validation engine</h2>
        </div>
        <div className="flex items-center gap-1.5 text-[11px] text-slate-500">
          {loading && <Loader2 size={12} className="animate-spin" />}
          {loading ? "calling backend…" : "live: /api/encrypt → /api/validate"}
        </div>
      </div>

      {error && (
        <div className="mb-3 text-xs text-red-400 bg-red-950 border border-red-900 rounded-md p-2">
          Couldn't reach the backend ({error}). Make sure it's running: <code className="font-mono">cd backend && npm start</code>
        </div>
      )}

      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        {/* Left: payload input + envelope */}
        <div className="space-y-3">
          <div className="flex flex-wrap gap-1.5">
            {Object.keys(SAMPLES).map((name) => (
              <button
                key={name}
                onClick={() => setPayload(SAMPLES[name])}
                className="text-[11px] px-2 py-1 rounded border border-slate-700 text-slate-400 hover:border-slate-500 hover:text-slate-200 transition-colors"
              >
                {name}
              </button>
            ))}
          </div>

          <textarea
            value={payload}
            onChange={(e) => setPayload(e.target.value)}
            rows={5}
            spellCheck={false}
            className="w-full bg-slate-900 border border-slate-800 rounded-md p-2.5 text-xs font-mono text-slate-300 focus:outline-none focus:border-cyan-700 resize-none"
          />

          {envelope && (
            <div className="bg-slate-900 border border-slate-800 rounded-md p-2.5 text-[11px] font-mono text-slate-500 space-y-1">
              <div><span className="text-slate-600">iv </span>{envelope.iv}</div>
              <div className="truncate"><span className="text-slate-600">ciphertext </span>{envelope.ciphertext.slice(0, 48)}{envelope.ciphertext.length > 48 ? "…" : ""}</div>
              <div><span className="text-slate-600">authTag </span>{envelope.authTag}</div>
            </div>
          )}

          <div className="flex items-center gap-2 pt-1">
            <button onClick={() => setPlaying((p) => !p)} disabled={!trace.length} className="flex items-center gap-1.5 text-xs px-3 py-1.5 rounded-md border border-slate-700 hover:border-slate-500 transition-colors disabled:opacity-40">
              {playing ? <Pause size={13} /> : <Play size={13} />}
              {playing ? "Pause" : "Play trace"}
            </button>
            <button onClick={() => setStepIdx((s) => Math.min(s + 1, trace.length - 1))} disabled={!trace.length} className="flex items-center gap-1.5 text-xs px-3 py-1.5 rounded-md border border-slate-700 hover:border-slate-500 transition-colors disabled:opacity-40">
              <SkipForward size={13} /> Step
            </button>
            <button onClick={() => { setStepIdx(0); setPlaying(false); }} disabled={!trace.length} className="flex items-center gap-1.5 text-xs px-3 py-1.5 rounded-md border border-slate-700 hover:border-slate-500 transition-colors disabled:opacity-40">
              <RotateCcw size={13} /> Reset
            </button>
            <span className="text-[11px] text-slate-500 ml-auto">step {trace.length ? Math.min(stepIdx, trace.length - 1) + 1 : 0}/{trace.length}</span>
          </div>

          <input
            type="range"
            min={0}
            max={Math.max(trace.length - 1, 0)}
            value={Math.min(stepIdx, trace.length - 1)}
            onChange={(e) => { setPlaying(false); setStepIdx(Number(e.target.value)); }}
            disabled={!trace.length}
            className="w-full accent-cyan-500"
          />
        </div>

        {/* Right: stack visualization */}
        <div className="bg-slate-900 border border-slate-800 rounded-md p-3 flex flex-col">
          <div className="flex items-center justify-between mb-2">
            <span className="text-[11px] uppercase tracking-wide text-slate-500">PDA stack</span>
            <span className="text-[11px] text-slate-500">depth {current.depth}</span>
          </div>

          <div className="flex-1 min-h-[180px] flex flex-col-reverse items-center justify-start gap-1 py-2">
            {current.stack.length === 0 && (
              <span className="text-[11px] text-slate-600 mb-auto">empty</span>
            )}
            {current.stack.map((sym, i) => (
              <div
                key={i}
                className={`w-28 text-center text-xs font-mono py-1.5 rounded border transition-all ${
                  i === current.stack.length - 1
                    ? "border-amber-600 bg-amber-950 text-amber-300"
                    : "border-slate-700 bg-slate-800 text-slate-400"
                }`}
              >
                {sym}
              </div>
            ))}
          </div>

          <div className="mt-2 pt-2 border-t border-slate-800 text-[11px] font-mono">
            <span className="text-slate-500">action </span>
            <span className={current.action === "PUSH" ? "text-amber-400" : current.action === "POP" ? "text-cyan-400" : isViolationStep ? "text-red-400" : "text-slate-400"}>
              {current.action}{current.symbol ? ` '${current.symbol}'` : ""}
            </span>
          </div>
        </div>
      </div>

      {/* Verdict */}
      {result && (
        <div className={`mt-4 rounded-md border p-3 flex items-start gap-2.5 ${result.valid ? "border-emerald-800 bg-emerald-950" : "border-red-900 bg-red-950"}`}>
          {result.valid ? <ShieldCheck size={16} className="text-emerald-400 mt-0.5 shrink-0" /> : <ShieldAlert size={16} className="text-red-400 mt-0.5 shrink-0" />}
          <div className="text-xs">
            <div className={result.valid ? "text-emerald-300" : "text-red-300"}>
              {result.valid ? `Payload accepted (${result.format?.toUpperCase()}, structurally valid)` : `Payload rejected — ${(result.violations || []).length} violation(s)`}
            </div>
            {result.violations?.length > 0 && (
              <ul className="mt-1.5 space-y-0.5 text-red-400/90 font-mono">
                {result.violations.map((v, i) => (
                  <li key={i}>· [{v.type}] {v.message}</li>
                ))}
              </ul>
            )}
          </div>
        </div>
      )}
    </div>
  );
}
