import React, { useMemo, useState } from 'react';
import axios from 'axios';
import {
  AlertTriangle, CheckCircle2, Download, Gauge, Globe2, Loader2, Network,
  Play, Route, Router, Server, ShieldAlert, ShieldCheck, TerminalSquare
} from 'lucide-react';
import { LIVE_DEVICE_TYPES } from '../vendorCatalog';

const API_URL = import.meta.env.VITE_API_URL || '';

const severityStyle = {
  critical: { bg:'#fef2f2', border:'#ef4444', text:'#991b1b' },
  high: { bg:'#fff7ed', border:'#f97316', text:'#9a3412' },
  medium: { bg:'#fefce8', border:'#eab308', text:'#854d0e' },
  low: { bg:'#eff6ff', border:'#3b82f6', text:'#1e40af' },
  info: { bg:'#f8fafc', border:'#94a3b8', text:'#334155' },
};

function Section({title, icon: Icon, children}) {
  return <section className="bg-white rounded-xl border border-gray-200 p-6">
    <div className="flex items-center gap-2 mb-4">{Icon && <Icon size={20} className="text-school-600"/>}<h3 className="text-lg font-bold text-gray-900">{title}</h3></div>
    {children}
  </section>;
}

function Pill({status}) {
  const map = {
    healthy: ['#dcfce7','#166534'], fault: ['#fee2e2','#991b1b'], review: ['#fef3c7','#854d0e'],
    fault_or_filtered: ['#fee2e2','#991b1b'], unknown_or_filtered: ['#fef3c7','#854d0e'],
    not_tested: ['#f1f5f9','#475569'], no_high_signal_exposure_found: ['#dcfce7','#166534'],
  };
  const [bg, color] = map[status] || ['#f1f5f9','#475569'];
  return <span style={{display:'inline-block',padding:'3px 8px',borderRadius:999,fontSize:12,fontWeight:700,background:bg,color}}>{String(status || 'unknown').replaceAll('_',' ')}</span>;
}

function TraceTable({trace}) {
  if (!trace?.hops?.length) return <p className="text-sm text-gray-500">No hop replies captured for this trace mode.</p>;
  return <div className="overflow-x-auto"><table style={{width:'100%',borderCollapse:'collapse'}}>
    <thead><tr><th style={{textAlign:'left',padding:7}}>Hop</th><th style={{textAlign:'left',padding:7}}>Address</th><th style={{textAlign:'left',padding:7}}>Evidence</th></tr></thead>
    <tbody>{trace.hops.map((hop, i)=><tr key={`${hop.hop}-${i}`} style={{borderTop:'1px solid #e2e8f0'}}><td style={{padding:7}}>{hop.hop}</td><td style={{padding:7}} className="font-mono text-sm">{hop.address || '*'}</td><td style={{padding:7}} className="font-mono text-xs">{hop.raw}</td></tr>)}</tbody>
  </table></div>;
}

export default function DeepNetworkEngineer() {
  const [target, setTarget] = useState('');
  const [ports, setPorts] = useState('22,53,80,443');
  const [dnsServer, setDnsServer] = useState('');
  const [runTrace, setRunTrace] = useState(true);
  const [securitySurface, setSecuritySurface] = useState(true);
  const [deviceEnabled, setDeviceEnabled] = useState(false);
  const [deviceHost, setDeviceHost] = useState('');
  const [deviceType, setDeviceType] = useState('cisco_ios');
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [secret, setSecret] = useState('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [result, setResult] = useState(null);

  const parsedPorts = useMemo(() => ports.split(',').map(v=>Number(v.trim())).filter(v=>Number.isInteger(v)&&v>0&&v<=65535), [ports]);

  const run = async () => {
    if (!target.trim()) return setError('Enter an authorized hostname or IP address.');
    if (!parsedPorts.length || parsedPorts.length > 16) return setError('Enter 1-16 valid TCP ports.');
    setLoading(true); setError(''); setResult(null);
    try {
      const response = await axios.post(`${API_URL}/api/v1/deep-diagnostics`, {
        target: target.trim(), ports: parsedPorts, dns_server: dnsServer.trim(), run_trace: runTrace,
        security_surface: securitySurface,
        device: {
          enabled: deviceEnabled, host: (deviceHost || target).trim(), username, password, secret,
          device_type: deviceType, port: 22,
          categories: ['basic','interfaces','errors','neighbors','routing','vlan','stp','mac','arp','security'],
        },
      });
      setResult(response.data);
    } catch (err) {
      setError(err.response?.data?.detail || 'Deep diagnostics failed. Verify target reachability and server diagnostic policy.');
    } finally {
      setPassword(''); setSecret(''); setLoading(false);
    }
  };

  const exportJson = () => {
    if (!result) return;
    const blob = new Blob([JSON.stringify(result,null,2)], {type:'application/json'});
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a'); a.href=url;
    a.download=`schoolnet-deep-diagnostics-${result.target || 'target'}-${new Date().toISOString().replace(/[:.]/g,'-')}.json`;
    a.click(); URL.revokeObjectURL(url);
  };

  const deep = result?.deep_diagnostics || {};
  const faultDomains = deep?.fault_domains || [];
  const exposure = deep?.security_exposure || {};
  const hypotheses = result?.hypotheses || [];
  const routeMatrix = deep?.route_matrix || [];
  const traces = deep?.trace_variants || {};
  const mtu = deep?.path_mtu || {};
  const dnsDeep = deep?.dns_deep || {};

  return <div className="p-6 space-y-6">
    <div className="bg-blue-50 border border-blue-200 rounded-xl p-4 flex items-start gap-3">
      <Network size={22} className="text-blue-600"/>
      <div><p className="font-bold text-blue-900">Deep Network Engineer</p><p className="text-sm text-blue-800">One-target, read-only troubleshooting across DNS, hostname/PTR, IPv4/IPv6 routing, policy routes, neighbor cache, UDP/ICMP/TCP traceroute, PMTU hints, TCP/HTTP/TLS, common management/service exposure, and optional deep OSPF/BGP/device evidence.</p></div>
    </div>

    <Section title="Target and engineer checks" icon={Globe2}>
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        <div><label className="text-sm font-bold text-gray-700">Hostname or IP</label><input value={target} onChange={e=>setTarget(e.target.value)} placeholder="switch01.example.internal or 10.0.0.10"/></div>
        <div><label className="text-sm font-bold text-gray-700">Expected TCP ports</label><input value={ports} onChange={e=>setPorts(e.target.value)} placeholder="22,53,80,443"/></div>
        <div><label className="text-sm font-bold text-gray-700">DNS resolver (optional)</label><input value={dnsServer} onChange={e=>setDnsServer(e.target.value)} placeholder="10.0.0.53"/></div>
        <div className="flex items-center gap-4" style={{paddingTop:24}}>
          <label className="flex items-center gap-2 text-sm"><input style={{width:'auto'}} type="checkbox" checked={runTrace} onChange={e=>setRunTrace(e.target.checked)}/> Multi-mode traceroute</label>
          <label className="flex items-center gap-2 text-sm"><input style={{width:'auto'}} type="checkbox" checked={securitySurface} onChange={e=>setSecuritySurface(e.target.checked)}/> Exposure review</label>
        </div>
      </div>
      <div className="flex gap-2 flex-wrap mt-4">
        <button className="btn secondary" onClick={()=>setPorts('22,23,53,80,443,830')}>Network device</button>
        <button className="btn secondary" onClick={()=>setPorts('53,80,443,445,3389,5985,5986')}>Windows/infra</button>
        <button className="btn secondary" onClick={()=>setPorts('22,80,443,6379,8080,8443,9200,27017')}>Linux/app/database</button>
      </div>
    </Section>

    <Section title="Optional deep device / Linux evidence" icon={TerminalSquare}>
      <label className="flex items-center gap-2 text-sm font-bold text-gray-700"><input style={{width:'auto'}} type="checkbox" checked={deviceEnabled} onChange={e=>setDeviceEnabled(e.target.checked)}/> Correlate live read-only device evidence, including deep routing state</label>
      {deviceEnabled && <div className="grid grid-cols-1 md:grid-cols-2 gap-4 mt-4">
        <div><label className="text-sm font-bold text-gray-700">Device host</label><input value={deviceHost} onChange={e=>setDeviceHost(e.target.value)} placeholder={target || '10.0.0.1'}/></div>
        <div><label className="text-sm font-bold text-gray-700">Platform</label><select value={deviceType} onChange={e=>setDeviceType(e.target.value)}>{LIVE_DEVICE_TYPES.map(item=><option key={item.id} value={item.id}>{item.name}</option>)}</select></div>
        <div><label className="text-sm font-bold text-gray-700">Read-only username</label><input value={username} onChange={e=>setUsername(e.target.value)} autoComplete="username"/></div>
        <div><label className="text-sm font-bold text-gray-700">Password</label><input type="password" value={password} onChange={e=>setPassword(e.target.value)} autoComplete="current-password"/></div>
        <div><label className="text-sm font-bold text-gray-700">Enable secret (optional)</label><input type="password" value={secret} onChange={e=>setSecret(e.target.value)}/></div>
      </div>}
      <p className="text-xs text-gray-500 mt-4">Requires ENABLE_LIVE_SSH=true and HTTPS before entering credentials. Commands are predefined read-only show/display/get diagnostics; unsupported vendor commands are reported instead of changing the device.</p>
    </Section>

    <div className="flex gap-3 flex-wrap"><button className="btn" onClick={run} disabled={loading}>{loading?<Loader2 size={18} className="animate-spin"/>:<Play size={18}/>} {loading?'Running deep diagnostics...':'Run Deep Troubleshooting'}</button>{result&&<button className="btn secondary" onClick={exportJson}><Download size={18}/> Export Engineer Passport</button>}</div>
    {error&&<div className="bg-red-50 border border-red-400 rounded-xl p-4 text-red-600 flex gap-3"><AlertTriangle size={20}/><span>{error}</span></div>}

    {result && <div className="space-y-6">
      <Section title="Engineer fault-domain matrix" icon={Gauge}>
        <div className="grid grid-cols-1 md:grid-cols-2 gap-3">{faultDomains.map((item,i)=><div key={i} className="bg-gray-50 rounded-xl p-4"><div className="flex justify-between gap-3"><strong>{item.domain}</strong><Pill status={item.status}/></div><p className="text-xs text-gray-600 mt-2 font-mono">{item.evidence || 'No evidence'}</p></div>)}</div>
        <div className="space-y-3 mt-6">{hypotheses.slice(0,8).map((item,i)=>{const s=severityStyle[item.severity]||severityStyle.info;return <div key={i} style={{background:s.bg,border:`1px solid ${s.border}`,borderRadius:12,padding:14}}><div className="flex justify-between gap-3"><strong style={{color:s.text}}>{i+1}. {item.title}</strong><span style={{color:s.text,fontWeight:700}}>{item.score}%</span></div><p className="text-sm mt-1"><strong>Evidence:</strong> {item.evidence}</p><p className="text-sm mt-1"><strong>Next:</strong> {item.next_step}</p></div>})}</div>
      </Section>

      <Section title="DNS, hostname and reverse lookup" icon={Globe2}>
        <div className="grid grid-cols-1 md:grid-cols-3 gap-4"><div><div className="text-xs text-gray-500 uppercase">Probe host</div><div className="font-mono text-sm">{deep.system_context?.probe_hostname || 'unknown'}</div></div><div><div className="text-xs text-gray-500 uppercase">Probe FQDN</div><div className="font-mono text-sm">{deep.system_context?.probe_fqdn || 'unknown'}</div></div><div><div className="text-xs text-gray-500 uppercase">Resolvers</div><div className="font-mono text-sm">{deep.system_context?.resolver_nameservers?.join(', ') || 'unknown'}</div></div></div>
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4 mt-4"><div><h4 className="font-bold">Forward DNS</h4>{Object.entries(dnsDeep.records || {}).map(([type,data])=><div key={type} className="text-sm mt-1"><strong>{type}:</strong> <span className="font-mono">{data.answers?.join(' | ') || 'no answer'}</span></div>)}</div><div><h4 className="font-bold">PTR / reverse</h4>{dnsDeep.reverse_dig?.map((item,i)=><div key={i} className="text-sm mt-1 font-mono">{item.address} → {item.answers?.join(' | ') || 'no PTR'}</div>)}</div></div>
        {dnsDeep.resolver_comparison?.compared && <div className="mt-4 bg-gray-50 rounded-xl p-4"><strong>Resolver comparison:</strong> <Pill status={dnsDeep.resolver_comparison.match?'healthy':'review'}/><div className="text-xs font-mono mt-2">system={JSON.stringify(dnsDeep.resolver_comparison.system_addresses)} selected={JSON.stringify(dnsDeep.resolver_comparison.selected_resolver_addresses)}</div></div>}
      </Section>

      <Section title="IP routing and path selection" icon={Route}>
        <div className="overflow-x-auto"><table style={{width:'100%',borderCollapse:'collapse'}}><thead><tr><th style={{textAlign:'left',padding:8}}>Destination</th><th style={{textAlign:'left',padding:8}}>Interface</th><th style={{textAlign:'left',padding:8}}>Next hop</th><th style={{textAlign:'left',padding:8}}>Source</th></tr></thead><tbody>{routeMatrix.map((r,i)=><tr key={i} style={{borderTop:'1px solid #e2e8f0'}}><td style={{padding:8}} className="font-mono text-sm">{r.address}</td><td style={{padding:8}}>{r.interface || '-'}</td><td style={{padding:8}} className="font-mono text-sm">{r.next_hop || 'on-link'}</td><td style={{padding:8}} className="font-mono text-sm">{r.source_ip || '-'}</td></tr>)}</tbody></table></div>
        <details className="mt-4"><summary className="font-bold cursor-pointer">Probe route table / policy rules / neighbor cache</summary><pre className="text-xs bg-gray-50 rounded-xl p-4 mt-2 overflow-x-auto">{deep.system_context?.routes_ipv4?.stdout || ''}{'\n\nIPv6:\n'}{deep.system_context?.routes_ipv6?.stdout || ''}{'\n\nRules:\n'}{deep.system_context?.policy_rules?.stdout || ''}{'\n\nNeighbors:\n'}{deep.system_context?.neighbors?.stdout || ''}</pre></details>
      </Section>

      {runTrace && <Section title="Multi-mode traceroute" icon={Router}>
        {['udp','icmp','tcp'].map(mode=><div key={mode} className="mb-6"><div className="flex items-center justify-between"><h4 className="font-bold uppercase">{mode} trace{mode==='tcp'&&traces[mode]?.tcp_port?` / TCP ${traces[mode].tcp_port}`:''}</h4><Pill status={traces[mode]?.ok?'healthy':'review'}/></div><div className="mt-2"><TraceTable trace={traces[mode]}/></div></div>)}
      </Section>}

      <Section title="Path MTU evidence" icon={Network}>
        <div className="flex items-center gap-3"><strong>Largest confirmed IP MTU:</strong><span className="font-mono">{mtu.largest_confirmed_ip_mtu || 'inconclusive'}</span></div><p className="text-xs text-gray-500 mt-2">{mtu.note}</p><div className="grid grid-cols-2 md:grid-cols-4 gap-3 mt-4">{mtu.attempts?.map((a,i)=><div key={i} className="bg-gray-50 rounded-xl p-3"><div className="font-bold">MTU {a.estimated_ip_mtu}</div><Pill status={a.success?'healthy':'review'}/></div>)}</div>
      </Section>

      <Section title="Common attack-surface review" icon={ShieldAlert}>
        {exposure.skipped ? <p className="text-sm text-gray-500">Exposure review disabled.</p> : <><p className="text-sm text-gray-600">Bounded reachability only; this does not exploit services or prove compromise.</p><div className="grid grid-cols-2 md:grid-cols-4 gap-3 mt-4">{exposure.tcp?.filter(x=>x.open).map(item=><div key={item.port} className="bg-gray-50 rounded-xl p-3"><div className="font-bold">TCP/{item.port}</div><div className="text-xs text-gray-500">{item.service}</div><Pill status="review"/></div>)}</div><div className="space-y-3 mt-4">{exposure.findings?.map((f,i)=>{const s=severityStyle[f.severity]||severityStyle.info;return <div key={i} style={{background:s.bg,border:`1px solid ${s.border}`,borderRadius:12,padding:14}}><strong style={{color:s.text}}>{f.severity.toUpperCase()} · {f.title}</strong><p className="text-sm mt-1">{f.impact}</p></div>})}</div>{!exposure.findings?.length&&<div className="bg-green-50 border border-green-200 rounded-xl p-4 mt-4 text-green-800"><CheckCircle2 size={18} style={{display:'inline',marginRight:8}}/>No high-signal exposure was identified in the bounded port set from this probe network.</div>}</>}
      </Section>

      <Section title="Target-specific device route evidence" icon={Server}>
        {deep.device_target_route?.collected ? <><div className="font-mono text-sm">$ {deep.device_target_route.command}</div><pre className="text-xs bg-gray-50 rounded-xl p-4 mt-2 overflow-x-auto">{deep.device_target_route.result?.raw || deep.device_target_route.result?.output || ''}</pre></> : <p className="text-sm text-gray-500">{deep.device_target_route?.error || 'Optional device route lookup was not collected.'}</p>}
      </Section>

      <div className="bg-emerald-50 border border-emerald-200 rounded-xl p-4 flex gap-3 text-emerald-900"><ShieldCheck size={20}/><p className="text-sm">No configuration changes or exploit attempts are performed. Findings are evidence from the SchoolNet server path and optional read-only device output; validate from the affected client, VRF, and change window before remediation.</p></div>
    </div>}
  </div>;
}
