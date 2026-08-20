import React, { useMemo, useState } from 'react';
import axios from 'axios';
import {
  Activity, AlertTriangle, CheckCircle2, Download, Globe2, Loader2, Network,
  Play, Radar, Route, Server, ShieldCheck, TerminalSquare, WifiOff
} from 'lucide-react';
import { LIVE_DEVICE_TYPES } from '../vendorCatalog';

const API_URL = import.meta.env.VITE_API_URL || '';

const severityStyle = {
  critical: { border: '#ef4444', background: '#fef2f2', color: '#991b1b' },
  high: { border: '#f97316', background: '#fff7ed', color: '#9a3412' },
  medium: { border: '#eab308', background: '#fefce8', color: '#854d0e' },
  low: { border: '#3b82f6', background: '#eff6ff', color: '#1e40af' },
  info: { border: '#64748b', background: '#f8fafc', color: '#334155' },
};

function Section({ title, icon: Icon, children }) {
  return (
    <section className="bg-white rounded-xl border border-gray-200 p-6">
      <div className="flex items-center gap-2 mb-4">
        {Icon && <Icon size={20} className="text-school-600" />}
        <h3 className="text-lg font-bold text-gray-900">{title}</h3>
      </div>
      {children}
    </section>
  );
}

function StatusPill({ ok, yes = 'OK', no = 'Failed' }) {
  return <span style={{display:'inline-block', padding:'3px 8px', borderRadius:999, fontSize:12, fontWeight:700, background: ok ? '#dcfce7' : '#fee2e2', color: ok ? '#166534' : '#991b1b'}}>{ok ? yes : no}</span>;
}

export default function IncidentInvestigator() {
  const [target, setTarget] = useState('');
  const [ports, setPorts] = useState('22,53,80,443');
  const [dnsServer, setDnsServer] = useState('');
  const [runTrace, setRunTrace] = useState(true);
  const [securitySurface, setSecuritySurface] = useState(false);
  const [deviceEnabled, setDeviceEnabled] = useState(false);
  const [deviceHost, setDeviceHost] = useState('');
  const [deviceType, setDeviceType] = useState('cisco_ios');
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [secret, setSecret] = useState('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [result, setResult] = useState(null);

  const parsedPorts = useMemo(() => ports.split(',').map(v => Number(v.trim())).filter(v => Number.isInteger(v) && v > 0 && v <= 65535), [ports]);

  const loadProfile = (profile) => {
    if (profile === 'network') setPorts('22,23,53,80,443,830');
    if (profile === 'web') setPorts('80,443,8080,8443');
    if (profile === 'infra') setPorts('22,53,80,443,445,3389');
  };

  const runInvestigation = async () => {
    if (!target.trim()) {
      setError('Enter an authorized hostname or IP address to investigate.');
      return;
    }
    if (!parsedPorts.length || parsedPorts.length > 16) {
      setError('Enter 1-16 valid TCP ports separated by commas.');
      return;
    }
    setLoading(true);
    setError('');
    setResult(null);
    try {
      const response = await axios.post(`${API_URL}/api/v1/investigate`, {
        target: target.trim(),
        ports: parsedPorts,
        dns_server: dnsServer.trim(),
        run_trace: runTrace,
        security_surface: securitySurface,
        device: {
          enabled: deviceEnabled,
          host: (deviceHost || target).trim(),
          username,
          password,
          secret,
          device_type: deviceType,
          port: 22,
          categories: ['basic','interfaces','errors','neighbors','routing','vlan','stp','security'],
        },
      });
      setResult(response.data);
    } catch (err) {
      setError(err.response?.data?.detail || 'Investigation failed. Verify the target, backend connectivity, and diagnostic policy.');
    } finally {
      setPassword('');
      setSecret('');
      setLoading(false);
    }
  };

  const exportJson = () => {
    if (!result) return;
    const blob = new Blob([JSON.stringify(result, null, 2)], {type:'application/json'});
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = `schoolnet-incident-${result.target || 'target'}-${new Date().toISOString().replace(/[:.]/g,'-')}.json`;
    link.click();
    URL.revokeObjectURL(url);
  };

  const openPorts = result?.services?.tcp?.filter(item => item.open) || [];
  const route = result?.path?.route || {};
  const ping = result?.path?.ping || {};
  const hypotheses = result?.hypotheses || [];

  return (
    <div className="p-6 space-y-6">
      <div className="bg-blue-50 border border-blue-200 rounded-xl p-4 flex items-start gap-3">
        <Radar size={22} className="text-blue-600" />
        <div>
          <p className="font-bold text-blue-900">Evidence Correlation Engine</p>
          <p className="text-sm text-blue-800">SchoolNet checks DNS, reverse lookup, ICMP, the server route, traceroute, TCP services, HTTP/TLS and optional read-only device evidence, then ranks likely causes. Probes originate from this SchoolNet server, so results describe this server's path/VRF perspective.</p>
        </div>
      </div>

      <Section title="Incident target" icon={Globe2}>
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          <div>
            <label className="text-sm font-bold text-gray-700">Hostname or IP</label>
            <input value={target} onChange={e => setTarget(e.target.value)} placeholder="10.250.31.10 or app.example.internal" />
          </div>
          <div>
            <label className="text-sm font-bold text-gray-700">Expected TCP ports</label>
            <input value={ports} onChange={e => setPorts(e.target.value)} placeholder="22,53,80,443" />
          </div>
          <div>
            <label className="text-sm font-bold text-gray-700">DNS server (optional)</label>
            <input value={dnsServer} onChange={e => setDnsServer(e.target.value)} placeholder="10.250.32.111" />
          </div>
          <div className="flex items-center gap-4" style={{paddingTop:24}}>
            <label className="flex items-center gap-2 text-sm"><input style={{width:'auto'}} type="checkbox" checked={runTrace} onChange={e => setRunTrace(e.target.checked)} /> Trace path</label>
            <label className="flex items-center gap-2 text-sm"><input style={{width:'auto'}} type="checkbox" checked={securitySurface} onChange={e => setSecuritySurface(e.target.checked)} /> Check management exposure</label>
          </div>
        </div>
        <div className="flex gap-2 flex-wrap mt-4">
          <button className="btn secondary" onClick={() => loadProfile('network')}>Network device profile</button>
          <button className="btn secondary" onClick={() => loadProfile('web')}>Web/service profile</button>
          <button className="btn secondary" onClick={() => loadProfile('infra')}>Server/infrastructure profile</button>
        </div>
      </Section>

      <Section title="Optional read-only device / Linux SSH evidence" icon={TerminalSquare}>
        <label className="flex items-center gap-2 text-sm font-bold text-gray-700">
          <input style={{width:'auto'}} type="checkbox" checked={deviceEnabled} onChange={e => setDeviceEnabled(e.target.checked)} />
          Collect a predefined read-only health snapshot from the affected device
        </label>
        {deviceEnabled && (
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4 mt-4">
            <div><label className="text-sm font-bold text-gray-700">Device host</label><input value={deviceHost} onChange={e => setDeviceHost(e.target.value)} placeholder={target || '10.0.0.1'} /></div>
            <div><label className="text-sm font-bold text-gray-700">Platform driver</label><select value={deviceType} onChange={e => setDeviceType(e.target.value)}>{LIVE_DEVICE_TYPES.map(item => <option key={item.id} value={item.id}>{item.name}</option>)}</select></div>
            <div><label className="text-sm font-bold text-gray-700">Read-only username</label><input value={username} onChange={e => setUsername(e.target.value)} autoComplete="username" /></div>
            <div><label className="text-sm font-bold text-gray-700">Password</label><input type="password" value={password} onChange={e => setPassword(e.target.value)} autoComplete="current-password" /></div>
            <div><label className="text-sm font-bold text-gray-700">Enable secret (optional)</label><input type="password" value={secret} onChange={e => setSecret(e.target.value)} /></div>
          </div>
        )}
        <p className="text-xs text-gray-500 mt-4">Credentials are sent only for this request and are not included in the result. Live SSH must be enabled by server policy. SchoolNet executes only its predefined read-only command catalog.</p>
      </Section>

      <div className="flex gap-3 flex-wrap">
        <button className="btn" onClick={runInvestigation} disabled={loading}>{loading ? <Loader2 size={18} className="animate-spin"/> : <Play size={18}/>} {loading ? 'Investigating...' : 'Investigate Incident'}</button>
        {result && <button className="btn secondary" onClick={exportJson}><Download size={18}/> Export Incident Passport</button>}
      </div>

      {error && <div className="bg-red-50 border border-red-400 rounded-xl p-4 text-red-600 flex gap-3"><AlertTriangle size={20}/><span>{error}</span></div>}

      {result && (
        <div className="space-y-6">
          <Section title="Engineer summary" icon={Activity}>
            <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
              <div className="bg-gray-50 rounded-xl p-4"><div className="text-xs text-gray-500 uppercase">State</div><div className="font-bold text-lg">{String(result.overall_state).replaceAll('_',' ')}</div></div>
              <div className="bg-gray-50 rounded-xl p-4"><div className="text-xs text-gray-500 uppercase">Confidence</div><div className="font-bold text-lg">{Math.round((result.confidence || 0) * 100)}%</div></div>
              <div className="bg-gray-50 rounded-xl p-4"><div className="text-xs text-gray-500 uppercase">Primary IP</div><div className="font-mono text-sm">{result.primary_address || 'unresolved'}</div></div>
              <div className="bg-gray-50 rounded-xl p-4"><div className="text-xs text-gray-500 uppercase">Open TCP</div><div className="font-bold text-lg">{openPorts.length}</div></div>
            </div>

            <div className="space-y-4 mt-6">
              {hypotheses.length ? hypotheses.map((item, index) => {
                const s = severityStyle[item.severity] || severityStyle.info;
                return <div key={index} style={{border:`1px solid ${s.border}`, background:s.background, borderRadius:12, padding:16}}>
                  <div className="flex justify-between gap-3 flex-wrap"><strong style={{color:s.color}}>{index + 1}. {item.title}</strong><span style={{color:s.color, fontWeight:700}}>{item.severity.toUpperCase()} · {item.score}%</span></div>
                  <p className="text-sm text-gray-700 mt-1"><strong>Evidence:</strong> {item.evidence}</p>
                  <p className="text-sm text-gray-700 mt-1"><strong>Next:</strong> {item.next_step}</p>
                </div>;
              }) : <div className="bg-green-50 border border-green-200 rounded-xl p-4 text-green-800"><CheckCircle2 size={18} style={{display:'inline', marginRight:8}}/>No clear fault signature was found from the collected evidence. Compare against a known-good baseline or repeat while the symptom is active.</div>}
            </div>
          </Section>

          <Section title="Network path" icon={Route}>
            <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
              <div><div className="text-xs text-gray-500 uppercase">DNS addresses</div><div className="font-mono text-sm mt-1">{result.dns?.addresses?.join(', ') || 'none'}</div></div>
              <div><div className="text-xs text-gray-500 uppercase">ICMP</div><div className="mt-1"><StatusPill ok={ping.reachable} yes={`Reachable${ping.avg_rtt_ms != null ? ` · ${ping.avg_rtt_ms} ms` : ''}`} no="No reply" /></div></div>
              <div><div className="text-xs text-gray-500 uppercase">Route</div><div className="text-sm mt-1">{route.interface || 'unknown'}{route.next_hop ? ` via ${route.next_hop}` : ''}{route.source_ip ? ` src ${route.source_ip}` : ''}</div></div>
            </div>
            {result.path?.traceroute?.hops?.length > 0 && <div className="mt-4 overflow-x-auto"><table style={{width:'100%', borderCollapse:'collapse'}}><thead><tr><th style={{textAlign:'left', padding:8}}>Hop</th><th style={{textAlign:'left', padding:8}}>Address</th><th style={{textAlign:'left', padding:8}}>Evidence</th></tr></thead><tbody>{result.path.traceroute.hops.map(h => <tr key={h.hop} style={{borderTop:'1px solid #e2e8f0'}}><td style={{padding:8}}>{h.hop}</td><td className="font-mono text-sm" style={{padding:8}}>{h.address || '*'}</td><td className="font-mono text-xs" style={{padding:8}}>{h.raw}</td></tr>)}</tbody></table></div>}
          </Section>

          <Section title="Service reachability" icon={Server}>
            <div className="overflow-x-auto"><table style={{width:'100%', borderCollapse:'collapse'}}><thead><tr><th style={{textAlign:'left',padding:8}}>Port</th><th style={{textAlign:'left',padding:8}}>State</th><th style={{textAlign:'left',padding:8}}>Latency</th><th style={{textAlign:'left',padding:8}}>Error</th></tr></thead><tbody>{result.services?.tcp?.map(item => <tr key={item.port} style={{borderTop:'1px solid #e2e8f0'}}><td style={{padding:8}} className="font-mono">{item.port}</td><td style={{padding:8}}><StatusPill ok={item.open} yes="Open" no="Closed/filtered" /></td><td style={{padding:8}}>{item.latency_ms} ms</td><td style={{padding:8}} className="text-xs text-gray-500">{item.error || ''}</td></tr>)}</tbody></table></div>
            {result.services?.http?.length > 0 && <div className="mt-4"><h4 className="font-bold">HTTP evidence</h4>{result.services.http.map((item,i) => <div key={i} className="text-sm mt-1 font-mono">{item.url || `port ${item.port}`} → {item.status || 'failed'} {item.reason || item.error || ''}</div>)}</div>}
            {result.services?.tls?.length > 0 && <div className="mt-4"><h4 className="font-bold">TLS evidence</h4>{result.services.tls.map((item,i) => <div key={i} className="text-sm mt-1">Port {item.port}: <StatusPill ok={item.verified} yes={`${item.protocol || 'TLS'} verified`} no={item.ok ? 'TLS reachable; certificate not verified' : 'TLS failed'} /> {item.days_remaining != null && <span> · {item.days_remaining} days remaining</span>}</div>)}</div>}
          </Section>

          <Section title="Security posture evidence" icon={ShieldCheck}>
            {result.security?.findings?.length ? result.security.findings.map((item,i) => {
              const s = severityStyle[item.severity] || severityStyle.info;
              return <div key={i} style={{borderLeft:`4px solid ${s.border}`, padding:'10px 12px', marginBottom:10, background:s.background}}><strong style={{color:s.color}}>{item.severity.toUpperCase()} · {item.title}</strong><div className="text-sm text-gray-700">{item.impact}</div></div>;
            }) : <div className="text-sm text-gray-600">No management-exposure or TLS finding was generated from the ports that were checked. This is not a full vulnerability assessment.</div>}
          </Section>

          {result.device_snapshot?.enabled && <Section title="Read-only device evidence" icon={Network}>
            {!result.device_snapshot.collected ? <div className="bg-yellow-100 rounded-xl p-4 text-yellow-800 flex gap-2"><WifiOff size={18}/>{result.device_snapshot.error || 'Device evidence was not collected.'}</div> : <>
              <div className="text-sm text-gray-600 mb-4">Collected from {result.device_snapshot.host} using {result.device_snapshot.device_type}. Credentials stored: no.</div>
              {result.device_snapshot.findings?.length ? result.device_snapshot.findings.map((item,i) => <div key={i} className="border border-gray-200 rounded-lg p-3 mb-2"><strong>{item.severity.toUpperCase()} · {item.title}</strong><p className="text-sm text-gray-600">{item.impact}</p><p className="text-xs font-mono text-gray-500">{item.evidence}</p></div>) : <div className="text-sm text-gray-600">No strong fault signature was extracted from the predefined snapshot. Review raw evidence if needed.</div>}
              <details className="mt-4"><summary className="cursor-pointer font-bold text-sm">Raw read-only command evidence</summary><pre className="bg-gray-900 text-gray-300 rounded-lg p-4 mt-2 text-xs overflow-x-auto">{JSON.stringify(result.device_snapshot.results, null, 2)}</pre></details>
            </>}
          </Section>}

          <Section title="Recommended engineer actions" icon={CheckCircle2}>
            <ol style={{paddingLeft:22, margin:0}}>{result.recommended_next_actions?.map((item,i) => <li key={i} className="text-sm text-gray-700 mb-3">{item}</li>)}</ol>
            <div className="bg-gray-50 border border-gray-200 rounded-xl p-4 text-xs text-gray-600 mt-4">{result.safety_note}</div>
          </Section>
        </div>
      )}
    </div>
  );
}
