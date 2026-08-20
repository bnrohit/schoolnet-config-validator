import React, { useEffect, useMemo, useState } from 'react';
import axios from 'axios';
import {
  Activity, AlertTriangle, Clock3, Download, GitCompareArrows, Globe2, Loader2,
  Network, Play, Printer, Route, Save, ShieldCheck, TerminalSquare
} from 'lucide-react';
import { LIVE_DEVICE_TYPES } from '../vendorCatalog';

const API_URL = import.meta.env.VITE_API_URL || '';

function Section({ title, icon: Icon, children }) {
  return <section className="bg-white rounded-xl border border-gray-200 p-6">
    <div className="flex items-center gap-2 mb-4">{Icon && <Icon size={20} className="text-school-600"/>}<h3 className="text-lg font-bold text-gray-900">{title}</h3></div>
    {children}
  </section>;
}

function HopStrip({ mode, hops = [], samples = {} }) {
  return <div className="mb-5">
    <div className="font-bold uppercase text-xs text-gray-500 mb-2">{mode} path</div>
    <div className="flex flex-wrap items-center gap-2">
      {hops.length ? hops.map((hop, idx) => {
        const sample = hop.address ? samples[hop.address] : null;
        const loss = sample?.packet_loss_percent;
        const bad = typeof loss === 'number' && loss >= 50;
        return <React.Fragment key={`${mode}-${idx}-${hop.address || 'x'}`}>
          <div title={hop.raw || ''} style={{minWidth:130,border:`1px solid ${bad ? '#f97316' : '#cbd5e1'}`,background: bad ? '#fff7ed' : '#f8fafc',borderRadius:12,padding:'10px 12px'}}>
            <div className="text-[11px] text-gray-500">Hop {hop.hop}</div>
            <div className="font-bold text-sm truncate" style={{maxWidth:190}}>{hop.display_name || hop.address || 'no reply'}</div>
            <div className="font-mono text-[11px] text-gray-500">{hop.address || '*'}</div>
            {sample && <div className="text-[11px] mt-1">loss {loss ?? '?'}% · avg {sample.avg_ms ?? '?'} ms · jitter {sample.jitter_ms ?? '?'} ms</div>}
          </div>
          {idx < hops.length - 1 && <span className="text-gray-400">→</span>}
        </React.Fragment>;
      }) : <span className="text-sm text-gray-500">No hop replies captured.</span>}
    </div>
  </div>;
}

export default function PathIntelligenceLab() {
  const [target, setTarget] = useState('');
  const [ports, setPorts] = useState('22,53,80,443');
  const [dnsServer, setDnsServer] = useState('');
  const [samples, setSamples] = useState(5);
  const [saveHistory, setSaveHistory] = useState(false);
  const [historyLabel, setHistoryLabel] = useState('');
  const [deviceEnabled, setDeviceEnabled] = useState(false);
  const [deviceHost, setDeviceHost] = useState('');
  const [deviceType, setDeviceType] = useState('cisco_ios');
  const [vrf, setVrf] = useState('');
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [secret, setSecret] = useState('');
  const [result, setResult] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [policy, setPolicy] = useState(null);
  const [history, setHistory] = useState([]);
  const [beforeId, setBeforeId] = useState('');
  const [afterId, setAfterId] = useState('');
  const [comparison, setComparison] = useState(null);

  const parsedPorts = useMemo(() => ports.split(',').map(v => Number(v.trim())).filter(v => Number.isInteger(v) && v > 0 && v <= 65535), [ports]);

  const refreshHistory = async () => {
    try {
      const response = await axios.get(`${API_URL}/api/v1/diagnostic-history`, { params: { limit: 50, target: target.trim() || undefined } });
      setHistory(response.data?.runs || []);
    } catch (_) {
      setHistory([]);
    }
  };

  useEffect(() => {
    axios.get(`${API_URL}/api/v1/runtime-policy`).then(r => setPolicy(r.data)).catch(() => setPolicy(null));
  }, []);

  useEffect(() => {
    if (policy?.diagnostic_history?.enabled) refreshHistory();
  }, [policy]);

  const run = async () => {
    if (!target.trim()) return setError('Enter an authorized hostname or IP address.');
    if (!parsedPorts.length || parsedPorts.length > 16) return setError('Enter 1-16 valid TCP ports.');
    setLoading(true); setError(''); setResult(null); setComparison(null);
    try {
      const response = await axios.post(`${API_URL}/api/v1/deep-diagnostics`, {
        target: target.trim(),
        ports: parsedPorts,
        dns_server: dnsServer.trim(),
        run_trace: true,
        security_surface: true,
        auto_application_probe: true,
        path_sample_count: Number(samples),
        save_history: saveHistory,
        history_label: historyLabel.trim(),
        device: {
          enabled: deviceEnabled,
          host: (deviceHost || target).trim(),
          username, password, secret,
          device_type: deviceType,
          port: 22,
          vrf: vrf.trim(),
          categories: ['basic','interfaces','errors','neighbors','routing','vlan','stp','mac','arp','security'],
        },
      });
      setResult(response.data);
      if (saveHistory) await refreshHistory();
    } catch (err) {
      setError(err.response?.data?.detail || 'Path intelligence failed. Verify target, policy, and backend reachability.');
    } finally {
      setPassword(''); setSecret(''); setLoading(false);
    }
  };

  const compare = async () => {
    if (!beforeId || !afterId || beforeId === afterId) return;
    try {
      const response = await axios.get(`${API_URL}/api/v1/diagnostic-history-compare`, { params: { before_id: beforeId, after_id: afterId } });
      setComparison(response.data);
    } catch (err) {
      setError(err.response?.data?.detail || 'History comparison failed.');
    }
  };

  const exportJson = () => {
    if (!result) return;
    const blob = new Blob([JSON.stringify(result, null, 2)], {type:'application/json'});
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a'); a.href = url;
    a.download = `schoolnet-path-intelligence-${result.target || 'target'}-${new Date().toISOString().replace(/[:.]/g,'-')}.json`;
    a.click(); URL.revokeObjectURL(url);
  };

  const path = result?.path_intelligence || {};
  const byMode = path?.hop_dns?.by_mode || {};
  const sampleMap = Object.fromEntries((path?.bounded_path_samples || []).map(item => [item.address, item]));
  const app = result?.application_assurance || {};

  return <div className="p-6 space-y-6">
    <div className="bg-indigo-50 border border-indigo-200 rounded-xl p-4 flex gap-3">
      <Network size={22} className="text-indigo-600"/>
      <div><p className="font-bold text-indigo-900">Path Intelligence & Drift Lab</p><p className="text-sm text-indigo-800">Combines DNS/PTR, UDP/ICMP/TCP path views, bounded per-hop loss/jitter sampling, application/TLS assurance, optional VRF-aware device route evidence, and before/after history. It does not perform indefinite monitoring or broad scanning.</p></div>
    </div>

    <Section title="Target and path profile" icon={Globe2}>
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        <div><label className="text-sm font-bold text-gray-700">Hostname or IP</label><input value={target} onChange={e=>setTarget(e.target.value)} placeholder="10.0.0.10 or app.internal"/></div>
        <div><label className="text-sm font-bold text-gray-700">Expected TCP ports</label><input value={ports} onChange={e=>setPorts(e.target.value)} /></div>
        <div><label className="text-sm font-bold text-gray-700">DNS resolver (optional)</label><input value={dnsServer} onChange={e=>setDnsServer(e.target.value)} placeholder={policy?.default_dns_server || 'enterprise resolver'} /></div>
        <div><label className="text-sm font-bold text-gray-700">Per-hop samples (3-10)</label><input type="number" min="3" max="10" value={samples} onChange={e=>setSamples(Math.max(3,Math.min(10,Number(e.target.value)||5)))} /></div>
      </div>
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4 mt-4">
        <label className="flex items-center gap-2 text-sm"><input style={{width:'auto'}} type="checkbox" checked={saveHistory} onChange={e=>setSaveHistory(e.target.checked)} disabled={!policy?.diagnostic_history?.enabled}/><Save size={16}/> Save diagnostic snapshot</label>
        <input value={historyLabel} onChange={e=>setHistoryLabel(e.target.value)} placeholder="Before firewall change / After maintenance" disabled={!saveHistory}/>
      </div>
      {!policy?.diagnostic_history?.enabled && <p className="text-xs text-gray-500 mt-2">History is opt-in on the server. Enable ENABLE_DIAGNOSTIC_HISTORY=true to retain diagnostic snapshots.</p>}
    </Section>

    <Section title="Optional target/next-hop route evidence" icon={TerminalSquare}>
      <label className="flex items-center gap-2 text-sm font-bold text-gray-700"><input style={{width:'auto'}} type="checkbox" checked={deviceEnabled} onChange={e=>setDeviceEnabled(e.target.checked)}/> Use predefined read-only SSH route/routing evidence</label>
      {deviceEnabled && <div className="grid grid-cols-1 md:grid-cols-2 gap-4 mt-4">
        <div><label className="text-sm font-bold text-gray-700">Device host</label><input value={deviceHost} onChange={e=>setDeviceHost(e.target.value)} placeholder={target || '10.0.0.1'}/></div>
        <div><label className="text-sm font-bold text-gray-700">Platform</label><select value={deviceType} onChange={e=>setDeviceType(e.target.value)}>{LIVE_DEVICE_TYPES.map(item=><option key={item.id} value={item.id}>{item.name}</option>)}</select></div>
        <div><label className="text-sm font-bold text-gray-700">VRF / routing instance (optional)</label><input value={vrf} onChange={e=>setVrf(e.target.value)} placeholder="MGMT or school-vrf"/></div>
        <div><label className="text-sm font-bold text-gray-700">Read-only username</label><input value={username} onChange={e=>setUsername(e.target.value)} /></div>
        <div><label className="text-sm font-bold text-gray-700">Password</label><input type="password" value={password} onChange={e=>setPassword(e.target.value)} /></div>
        <div><label className="text-sm font-bold text-gray-700">Enable secret (optional)</label><input type="password" value={secret} onChange={e=>setSecret(e.target.value)} /></div>
      </div>}
      <p className="text-xs text-gray-500 mt-3">Live credentials require HTTPS by default. SchoolNet uses predefined read-only commands and does not store credentials in history.</p>
    </Section>

    <div className="flex gap-3 flex-wrap">
      <button className="btn" onClick={run} disabled={loading}>{loading?<Loader2 size={18} className="animate-spin"/>:<Play size={18}/>} {loading?'Building path intelligence...':'Run Path Intelligence'}</button>
      {result && <button className="btn secondary" onClick={exportJson}><Download size={18}/> Export JSON</button>}
      {result && <button className="btn secondary" onClick={()=>window.print()}><Printer size={18}/> Print / Save PDF</button>}
    </div>
    {error && <div className="bg-red-50 border border-red-300 rounded-xl p-4 text-red-700 flex gap-3"><AlertTriangle size={20}/>{error}</div>}

    {result && <>
      <Section title="Interactive path view" icon={Route}>
        <HopStrip mode="UDP" hops={byMode.udp || []} samples={sampleMap}/>
        <HopStrip mode="ICMP" hops={byMode.icmp || []} samples={sampleMap}/>
        <HopStrip mode="TCP" hops={byMode.tcp || []} samples={sampleMap}/>
        <div className="grid grid-cols-1 md:grid-cols-3 gap-3 mt-4">
          <div className="bg-gray-50 rounded-xl p-4"><div className="text-xs text-gray-500 uppercase">First divergence</div><div className="font-bold">{path.trace_mode_comparison?.first_address_divergence_hop ? `Hop ${path.trace_mode_comparison.first_address_divergence_hop}` : 'No address divergence observed'}</div></div>
          <div className="bg-gray-50 rounded-xl p-4"><div className="text-xs text-gray-500 uppercase">Application</div><div className="font-bold">{app.application_status || 'not tested'}</div></div>
          <div className="bg-gray-50 rounded-xl p-4"><div className="text-xs text-gray-500 uppercase">TLS</div><div className="font-bold">{app.tls_status || 'not tested'}</div></div>
        </div>
      </Section>

      <Section title="Per-hop loss, latency and jitter snapshot" icon={Activity}>
        <div className="overflow-x-auto"><table style={{width:'100%',borderCollapse:'collapse'}}><thead><tr><th style={{textAlign:'left',padding:8}}>Hop IP</th><th style={{textAlign:'left',padding:8}}>Loss</th><th style={{textAlign:'left',padding:8}}>Min</th><th style={{textAlign:'left',padding:8}}>Avg</th><th style={{textAlign:'left',padding:8}}>Max</th><th style={{textAlign:'left',padding:8}}>Jitter</th></tr></thead><tbody>{(path.bounded_path_samples||[]).map(item=><tr key={item.address} style={{borderTop:'1px solid #e2e8f0'}}><td className="font-mono text-sm" style={{padding:8}}>{item.address}</td><td style={{padding:8}}>{item.packet_loss_percent ?? '?'}%</td><td style={{padding:8}}>{item.min_ms ?? '?'} ms</td><td style={{padding:8}}>{item.avg_ms ?? '?'} ms</td><td style={{padding:8}}>{item.max_ms ?? '?'} ms</td><td style={{padding:8}}>{item.jitter_ms ?? '?'} ms</td></tr>)}</tbody></table></div>
        <p className="text-xs text-gray-500 mt-3">Per-hop ICMP loss is not automatically forwarding loss; routers commonly rate-limit control-plane replies. Compare downstream hops and application reachability.</p>
      </Section>

      <Section title="Forward / return route evidence" icon={ShieldCheck}>
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          {[['Device → target',path.device_forward_route_evidence],['Device → probe source',path.return_path_route_evidence]].map(([title,item])=><div key={title} className="bg-gray-50 rounded-xl p-4"><div className="font-bold">{title}</div><div className="text-xs text-gray-500 mt-1">VRF: {item?.vrf || 'default/global'}</div><div className="font-mono text-xs mt-2">{item?.command || item?.reason || item?.error || 'not collected'}</div>{item?.result && <pre className="text-xs mt-2 whitespace-pre-wrap overflow-x-auto">{String(item.result).slice(0,5000)}</pre>}</div>)}
        </div>
        <p className="text-xs text-gray-500 mt-3">This is route evidence, not mathematical proof of path symmetry. Use it to detect obvious return-route or VRF discrepancies.</p>
      </Section>
    </>}

    {policy?.diagnostic_history?.enabled && <Section title="Diagnostic history & drift comparison" icon={Clock3}>
      <div className="flex gap-2 flex-wrap mb-4"><button className="btn secondary" onClick={refreshHistory}>Refresh history</button></div>
      <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
        <select value={beforeId} onChange={e=>setBeforeId(e.target.value)}><option value="">Before snapshot</option>{history.map(run=><option key={run.id} value={run.id}>#{run.id} {run.label || run.target} · {new Date(run.created_at).toLocaleString()}</option>)}</select>
        <select value={afterId} onChange={e=>setAfterId(e.target.value)}><option value="">After snapshot</option>{history.map(run=><option key={run.id} value={run.id}>#{run.id} {run.label || run.target} · {new Date(run.created_at).toLocaleString()}</option>)}</select>
        <button className="btn" onClick={compare} disabled={!beforeId || !afterId || beforeId===afterId}><GitCompareArrows size={18}/> Compare</button>
      </div>
      {comparison && <div className="mt-5 space-y-3">
        <div className="grid grid-cols-1 md:grid-cols-4 gap-3">
          <div className="bg-gray-50 rounded-xl p-4"><div className="text-xs text-gray-500">Open TCP added</div><div className="font-mono text-sm">{comparison.open_tcp_delta?.added?.join(', ') || 'none'}</div></div>
          <div className="bg-gray-50 rounded-xl p-4"><div className="text-xs text-gray-500">Open TCP removed</div><div className="font-mono text-sm">{comparison.open_tcp_delta?.removed?.join(', ') || 'none'}</div></div>
          <div className="bg-gray-50 rounded-xl p-4"><div className="text-xs text-gray-500">Security findings</div><div className="font-bold">{comparison.security_findings?.before} → {comparison.security_findings?.after}</div></div>
          <div className="bg-gray-50 rounded-xl p-4"><div className="text-xs text-gray-500">Trace path changed</div><div className="font-bold">{comparison.trace_sequences_changed ? 'Yes' : 'No'}</div></div>
        </div>
        {(comparison.fault_domain_changes||[]).map((item,i)=><div key={i} className="border border-gray-200 rounded-xl p-3"><strong>{item.domain}</strong>: {item.before || 'unknown'} → {item.after || 'unknown'}</div>)}
      </div>}
    </Section>}
  </div>;
}
