import React, { useState } from 'react';
import axios from 'axios';
import {
  GitCompareArrows, ShieldAlert, Loader2, Fingerprint, Network, Route,
  Shield, Server, Cable, Activity, ClipboardCheck, RotateCcw, Download,
  AlertTriangle, CheckCircle2, LockKeyhole
} from 'lucide-react';
import { OFFLINE_VENDORS } from '../vendorCatalog';

const API_URL = import.meta.env.VITE_API_URL || '';

const riskTone = {
  critical: 'bg-red-50 border-red-300 text-red-900',
  high: 'bg-orange-50 border-orange-300 text-orange-900',
  medium: 'bg-amber-50 border-amber-300 text-amber-900',
  low: 'bg-blue-50 border-blue-300 text-blue-900',
  minimal: 'bg-emerald-50 border-emerald-300 text-emerald-900',
};

const gateTone = {
  BLOCK: 'bg-red-600 text-white',
  HOLD: 'bg-orange-600 text-white',
  CAUTION: 'bg-amber-500 text-slate-950',
  REVIEW: 'bg-emerald-600 text-white',
};

const domainMeta = {
  management_plane: { label: 'Management', icon: LockKeyhole },
  routing_control_plane: { label: 'Routing', icon: Route },
  layer2_forwarding: { label: 'Layer 2', icon: Network },
  security_policy: { label: 'Security Policy', icon: Shield },
  network_services: { label: 'Network Services', icon: Server },
  interface_connectivity: { label: 'Interfaces', icon: Cable },
};

function StepCard({ title, icon: Icon, items, tone = 'slate' }) {
  if (!items?.length) return null;
  const tones = {
    blue: 'bg-blue-50 border-blue-200 text-blue-900',
    amber: 'bg-amber-50 border-amber-200 text-amber-950',
    slate: 'bg-slate-50 border-slate-200 text-slate-800',
    green: 'bg-emerald-50 border-emerald-200 text-emerald-900',
  };
  return (
    <div className={`rounded-xl border p-4 ${tones[tone] || tones.slate}`}>
      <div className="flex items-center gap-2 font-bold text-sm mb-3"><Icon size={17}/>{title}</div>
      <ol className="list-decimal pl-5 space-y-2 text-sm">
        {items.map((item, i) => <li key={i}>{item}</li>)}
      </ol>
    </div>
  );
}

export default function ChangeImpactLab() {
  const [beforeConfig, setBeforeConfig] = useState('');
  const [afterConfig, setAfterConfig] = useState('');
  const [vendor, setVendor] = useState('auto');
  const [result, setResult] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);

  const analyze = async () => {
    if (!beforeConfig.trim() || !afterConfig.trim()) {
      setError('Paste both the current configuration and the proposed configuration.');
      return;
    }
    setLoading(true);
    setError(null);
    setResult(null);
    try {
      const response = await axios.post(`${API_URL}/api/v1/change-impact`, {
        before_config: beforeConfig,
        after_config: afterConfig,
        vendor,
      });
      setResult(response.data);
    } catch (err) {
      setError(err.response?.data?.detail || 'Change impact analysis failed.');
    } finally {
      setLoading(false);
    }
  };

  const downloadPassport = () => {
    if (!result) return;
    const payload = {
      generated_at: new Date().toISOString(),
      product: 'SchoolNet Change Impact Lab',
      ...result,
    };
    const blob = new Blob([JSON.stringify(payload, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = 'schoolnet-change-passport.json';
    a.click();
    URL.revokeObjectURL(url);
  };

  const riskClass = result ? (riskTone[result.risk_label] || riskTone.medium) : '';
  const gate = result?.change_gate;

  return (
    <div className="max-w-6xl mx-auto space-y-6">
      <div className="flex items-start gap-3">
        <div className="p-2.5 rounded-xl bg-indigo-50 text-indigo-700 border border-indigo-200"><GitCompareArrows size={26}/></div>
        <div>
          <h1 className="text-2xl font-bold text-slate-950">Change Impact Lab</h1>
          <p className="text-slate-600 mt-1">Pre-flight a proposed network change before touching production. Compare current vs proposed config, estimate blast radius, detect lockout/outage risks, and generate a rollback-aware validation runbook.</p>
        </div>
      </div>

      <div className="rounded-xl border border-indigo-200 bg-indigo-50 p-4 flex items-start gap-3">
        <ShieldAlert className="text-indigo-700 mt-0.5" size={20}/>
        <div className="text-sm text-indigo-950">
          <p className="font-bold">Offline safety gate — never auto-deploys.</p>
          <p className="mt-1">SchoolNet analyzes sanitized text only. It cannot know every physical dependency or runtime condition, so high-risk results require live pre-checks, human approval, and a verified recovery path.</p>
        </div>
      </div>

      <div className="bg-white rounded-xl border border-slate-200 shadow-sm overflow-hidden">
        <div className="p-4 border-b border-slate-100 flex items-center justify-between gap-3 flex-wrap">
          <div>
            <p className="text-sm font-semibold text-slate-900">Platform</p>
            <p className="text-xs text-slate-500">Auto-detect is recommended.</p>
          </div>
          <select value={vendor} onChange={(e) => setVendor(e.target.value)} className="bg-slate-50 border border-slate-300 rounded-lg px-3 py-2 text-sm min-w-64">
            {OFFLINE_VENDORS.map(v => <option key={v.id} value={v.id}>{v.name}</option>)}
          </select>
        </div>

        <div className="grid grid-cols-1 lg:grid-cols-2">
          <div className="p-4 lg:border-r border-slate-100">
            <div className="flex items-center justify-between mb-2">
              <div>
                <p className="font-bold text-slate-900">Current / Before</p>
                <p className="text-xs text-slate-500">Known-good configuration snapshot</p>
              </div>
            </div>
            <textarea
              value={beforeConfig}
              onChange={(e) => setBeforeConfig(e.target.value)}
              placeholder="Paste the sanitized current running configuration..."
              className="w-full h-80 p-4 font-mono text-xs bg-slate-950 text-emerald-300 rounded-xl resize-y focus:outline-none focus:ring-2 focus:ring-indigo-500"
              spellCheck={false}
            />
          </div>
          <div className="p-4">
            <div className="mb-2">
              <p className="font-bold text-slate-900">Proposed / After</p>
              <p className="text-xs text-slate-500">Configuration you intend to deploy</p>
            </div>
            <textarea
              value={afterConfig}
              onChange={(e) => setAfterConfig(e.target.value)}
              placeholder="Paste the sanitized proposed configuration..."
              className="w-full h-80 p-4 font-mono text-xs bg-slate-950 text-cyan-300 rounded-xl resize-y focus:outline-none focus:ring-2 focus:ring-indigo-500"
              spellCheck={false}
            />
          </div>
        </div>

        <div className="p-4 bg-slate-50 border-t border-slate-100 flex justify-end">
          <button onClick={analyze} disabled={loading} className="px-5 py-2.5 rounded-lg bg-indigo-700 text-white font-semibold text-sm hover:bg-indigo-800 disabled:opacity-50 flex items-center gap-2">
            {loading ? <Loader2 size={17} className="animate-spin"/> : <GitCompareArrows size={17}/>} {loading ? 'Analyzing change...' : 'Run Change Pre-Flight'}
          </button>
        </div>
      </div>

      {error && <div className="rounded-xl border border-red-200 bg-red-50 p-4 text-red-800 flex gap-2"><AlertTriangle size={19}/><span>{error}</span></div>}

      {result && (
        <div className="space-y-6">
          <div className={`rounded-2xl border p-5 ${riskClass}`}>
            <div className="flex items-start justify-between gap-4 flex-wrap">
              <div>
                <p className="text-xs font-bold uppercase tracking-widest opacity-70">Pre-change decision gate</p>
                <div className="flex items-center gap-3 mt-2 flex-wrap">
                  <span className={`px-3 py-1.5 rounded-lg text-sm font-black tracking-wide ${gateTone[gate?.status] || gateTone.REVIEW}`}>{gate?.status || 'REVIEW'}</span>
                  <h2 className="text-2xl font-black">Risk {result.risk_score}/100 · {result.risk_label}</h2>
                </div>
                <p className="mt-2 text-sm max-w-3xl">{gate?.reason}</p>
              </div>
              <button onClick={downloadPassport} className="px-3 py-2 rounded-lg border border-current/20 bg-white/60 text-sm font-semibold flex items-center gap-2"><Download size={16}/> Export Change Passport</button>
            </div>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-4 gap-3">
            <div className="bg-white border border-slate-200 rounded-xl p-4">
              <p className="text-xs uppercase tracking-wider text-slate-500 font-bold">Changed lines</p>
              <p className="text-3xl font-black text-slate-950 mt-1">{result.change_summary?.total_changed_lines}</p>
              <p className="text-xs text-slate-500 mt-1">{result.change_summary?.change_density_percent}% of baseline</p>
            </div>
            <div className="bg-white border border-slate-200 rounded-xl p-4">
              <p className="text-xs uppercase tracking-wider text-slate-500 font-bold">Risk events</p>
              <p className="text-3xl font-black text-slate-950 mt-1">{result.high_risk_events?.length || 0}</p>
              <p className="text-xs text-slate-500 mt-1">Evidence-backed signatures</p>
            </div>
            <div className="bg-white border border-slate-200 rounded-xl p-4">
              <p className="text-xs uppercase tracking-wider text-slate-500 font-bold">VLAN delta</p>
              <p className="text-lg font-black text-slate-950 mt-1">+{result.vlan_delta?.added?.length || 0} / −{result.vlan_delta?.removed?.length || 0}</p>
              <p className="text-xs text-slate-500 mt-1">Created / removed</p>
            </div>
            <div className="bg-white border border-slate-200 rounded-xl p-4">
              <p className="text-xs uppercase tracking-wider text-slate-500 font-bold flex items-center gap-1"><Fingerprint size={14}/> Config DNA</p>
              <p className="font-mono text-xs text-slate-700 mt-2 break-all">{result.configuration_dna?.after}</p>
              <p className="text-xs text-slate-500 mt-1">Semantic fingerprint</p>
            </div>
          </div>

          <div className="bg-white border border-slate-200 rounded-xl p-5">
            <h3 className="font-bold text-slate-950 flex items-center gap-2"><Activity size={19}/> Estimated Blast Radius</h3>
            <p className="text-sm text-slate-500 mt-1">Domains touched by the proposed configuration diff.</p>
            <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-6 gap-3 mt-4">
              {Object.entries(domainMeta).map(([key, meta]) => {
                const Icon = meta.icon;
                const active = result.blast_radius?.[key];
                return (
                  <div key={key} className={`rounded-xl border p-3 text-center ${active ? 'border-orange-200 bg-orange-50 text-orange-900' : 'border-slate-200 bg-slate-50 text-slate-400'}`}>
                    <Icon size={20} className="mx-auto"/>
                    <p className="text-xs font-bold mt-2">{meta.label}</p>
                    <p className="text-[11px] mt-1">{active ? 'Affected' : 'No diff signal'}</p>
                  </div>
                );
              })}
            </div>
          </div>

          {result.high_risk_events?.length > 0 && (
            <div className="bg-white border border-slate-200 rounded-xl p-5">
              <h3 className="font-bold text-slate-950 flex items-center gap-2"><ShieldAlert size={19}/> High-Impact Change Signals</h3>
              <div className="space-y-3 mt-4">
                {result.high_risk_events.map((event, i) => (
                  <div key={`${event.id}-${i}`} className="rounded-xl border border-slate-200 p-4">
                    <div className="flex items-center gap-2 flex-wrap">
                      <span className={`text-xs font-black uppercase px-2 py-1 rounded ${event.severity === 'critical' ? 'bg-red-100 text-red-800' : 'bg-orange-100 text-orange-800'}`}>{event.severity}</span>
                      <span className="text-xs bg-slate-100 text-slate-600 px-2 py-1 rounded">{event.direction}</span>
                      <span className="text-xs text-slate-500">{event.domain}</span>
                    </div>
                    <p className="font-bold text-slate-950 mt-2">{event.message}</p>
                    <p className="text-sm text-slate-600 mt-1">{event.impact}</p>
                    <pre className="mt-3 text-xs bg-slate-950 text-amber-300 p-3 rounded-lg overflow-x-auto whitespace-pre-wrap">{event.evidence}</pre>
                  </div>
                ))}
              </div>
            </div>
          )}

          <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
            <StepCard title="Pre-change evidence to capture" icon={ClipboardCheck} items={result.pre_change_checks} tone="blue"/>
            <StepCard title="Controlled change sequence" icon={Shield} items={result.controlled_change_sequence} tone="amber"/>
            <StepCard title="Rollback contract" icon={RotateCcw} items={result.rollback_plan} tone="slate"/>
            <StepCard title="Post-change proof" icon={CheckCircle2} items={result.post_change_validation} tone="green"/>
          </div>

          {(result.routing_protocol_delta?.added?.length > 0 || result.routing_protocol_delta?.removed?.length > 0) && (
            <div className="bg-white border border-slate-200 rounded-xl p-5">
              <h3 className="font-bold text-slate-950 flex items-center gap-2"><Route size={19}/> Routing Protocol Delta</h3>
              <div className="grid grid-cols-1 md:grid-cols-2 gap-3 mt-3 text-sm">
                <div className="rounded-lg bg-emerald-50 border border-emerald-200 p-3"><strong>Added:</strong> {result.routing_protocol_delta?.added?.join(', ') || 'None'}</div>
                <div className="rounded-lg bg-red-50 border border-red-200 p-3"><strong>Removed:</strong> {result.routing_protocol_delta?.removed?.join(', ') || 'None'}</div>
              </div>
            </div>
          )}

          <div className="bg-white border border-slate-200 rounded-xl overflow-hidden">
            <div className="p-4 border-b border-slate-100">
              <h3 className="font-bold text-slate-950">Sanitized Diff Preview</h3>
              <p className="text-xs text-slate-500 mt-1">Bounded preview for review; secrets are sanitized by the API before analysis.</p>
            </div>
            <pre className="p-4 max-h-96 overflow-auto bg-slate-950 text-xs text-slate-200 whitespace-pre">{result.diff_preview?.join('\n') || 'No operational line changes detected.'}</pre>
          </div>

          <div className="rounded-xl border border-slate-200 bg-slate-50 p-4 text-xs text-slate-600">{result.disclaimer}</div>
        </div>
      )}
    </div>
  );
}
