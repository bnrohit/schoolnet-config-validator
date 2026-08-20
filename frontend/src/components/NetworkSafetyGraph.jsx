import React, { useMemo, useState } from 'react';
import axios from 'axios';
import {
  Network, Plus, Trash2, Loader2, ShieldAlert, ShieldCheck, Activity,
  GitBranch, Download, FlaskConical, Router, Cable, Waypoints, AlertTriangle,
  CheckCircle2, CircleDot, RefreshCcw, Route, ServerCog
} from 'lucide-react';
import { OFFLINE_VENDORS } from '../vendorCatalog';

const API_URL = import.meta.env.VITE_API_URL || '';

const emptyDevice = (idx = 0) => ({
  name: `device-${idx + 1}`,
  vendor: 'auto',
  config_text: '',
  proposed_config: '',
  neighbor_text: '',
});

const severityStyle = {
  critical: 'border-red-300 bg-red-50 text-red-900',
  high: 'border-orange-300 bg-orange-50 text-orange-900',
  medium: 'border-amber-300 bg-amber-50 text-amber-900',
  low: 'border-blue-200 bg-blue-50 text-blue-900',
  info: 'border-slate-200 bg-slate-50 text-slate-800',
};

const gateStyle = {
  BLOCK: 'bg-red-100 text-red-800 border-red-300',
  HOLD: 'bg-orange-100 text-orange-800 border-orange-300',
  CAUTION: 'bg-amber-100 text-amber-800 border-amber-300',
  REVIEW: 'bg-blue-100 text-blue-800 border-blue-300',
};

function DeviceEditor({ device, index, onChange, onRemove, removable }) {
  const patch = (key, value) => onChange(index, { ...device, [key]: value });
  return (
    <div className="rounded-2xl border border-slate-200 bg-white shadow-sm overflow-hidden">
      <div className="flex items-center justify-between px-4 py-3 bg-slate-50 border-b border-slate-200">
        <div className="flex items-center gap-2">
          <Router size={18} className="text-slate-600" />
          <strong className="text-slate-900">Device {index + 1}</strong>
        </div>
        {removable && (
          <button onClick={() => onRemove(index)} className="text-slate-500 hover:text-red-600" title="Remove device">
            <Trash2 size={18} />
          </button>
        )}
      </div>
      <div className="p-4 space-y-3">
        <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
          <label className="text-sm font-semibold text-slate-700">
            Device name
            <input value={device.name} onChange={e => patch('name', e.target.value)} className="mt-1 w-full rounded-lg border border-slate-300 px-3 py-2 font-mono text-sm" placeholder="core01" />
          </label>
          <label className="text-sm font-semibold text-slate-700">
            Platform
            <select value={device.vendor} onChange={e => patch('vendor', e.target.value)} className="mt-1 w-full rounded-lg border border-slate-300 px-3 py-2 text-sm bg-white">
              {OFFLINE_VENDORS.map(v => <option key={v.id} value={v.id}>{v.name}</option>)}
            </select>
          </label>
        </div>
        <label className="block text-sm font-semibold text-slate-700">
          Current sanitized config <span className="text-red-600">*</span>
          <textarea value={device.config_text} onChange={e => patch('config_text', e.target.value)} rows={9} className="mt-1 w-full rounded-xl border border-slate-300 p-3 font-mono text-xs leading-5" placeholder="Paste current sanitized running configuration..." />
        </label>
        <div className="grid grid-cols-1 xl:grid-cols-2 gap-3">
          <label className="block text-sm font-semibold text-slate-700">
            Proposed config <span className="font-normal text-slate-400">(optional)</span>
            <textarea value={device.proposed_config} onChange={e => patch('proposed_config', e.target.value)} rows={6} className="mt-1 w-full rounded-xl border border-slate-300 p-3 font-mono text-xs leading-5" placeholder="Paste proposed post-change config to calculate network-wide impact..." />
          </label>
          <label className="block text-sm font-semibold text-slate-700">
            Neighbor evidence <span className="font-normal text-slate-400">(optional, recommended)</span>
            <textarea value={device.neighbor_text} onChange={e => patch('neighbor_text', e.target.value)} rows={6} className="mt-1 w-full rounded-xl border border-slate-300 p-3 font-mono text-xs leading-5" placeholder="Paste read-only show cdp/lldp neighbors output or equivalent..." />
          </label>
        </div>
      </div>
    </div>
  );
}

function TopologyGraph({ nodes = [], edges = [], propagation = [] }) {
  const width = 900;
  const height = 440;
  const centerX = width / 2;
  const centerY = height / 2;
  const radius = Math.min(310, Math.max(120, 65 * nodes.length));
  const positions = useMemo(() => {
    const map = {};
    nodes.forEach((node, i) => {
      const angle = (Math.PI * 2 * i) / Math.max(1, nodes.length) - Math.PI / 2;
      map[node.id] = { x: centerX + Math.cos(angle) * radius, y: centerY + Math.sin(angle) * Math.min(radius, 160) };
    });
    return map;
  }, [nodes, radius]);

  const propagated = new Set(propagation.map(p => p.device_id));
  if (!nodes.length) return null;

  return (
    <div className="rounded-2xl border border-slate-200 bg-slate-950 overflow-hidden">
      <div className="px-4 py-3 border-b border-slate-800 flex items-center justify-between">
        <div>
          <p className="font-semibold text-white flex items-center gap-2"><Network size={18}/> Inferred Network Safety Graph</p>
          <p className="text-xs text-slate-400 mt-1">Solid relationships are evidence-backed; confidence is shown on each link.</p>
        </div>
        <span className="text-xs text-slate-400">{nodes.length} nodes · {edges.length} relationships</span>
      </div>
      <div className="overflow-x-auto">
        <svg viewBox={`0 0 ${width} ${height}`} className="w-full min-w-[760px] h-[440px]">
          {edges.map(edge => {
            const a = positions[edge.source], b = positions[edge.target];
            if (!a || !b) return null;
            const mx = (a.x + b.x) / 2, my = (a.y + b.y) / 2;
            return (
              <g key={edge.id}>
                <line x1={a.x} y1={a.y} x2={b.x} y2={b.y} stroke="#64748b" strokeWidth={edge.kind === 'observed_neighbor' ? 3 : 2} strokeDasharray={edge.confidence < 0.8 ? '7 5' : undefined} />
                <rect x={mx - 42} y={my - 12} width="84" height="24" rx="7" fill="#0f172a" stroke="#475569" />
                <text x={mx} y={my + 4} textAnchor="middle" fill="#cbd5e1" fontSize="11">{Math.round(edge.confidence * 100)}% {edge.kind.replaceAll('_', ' ')}</text>
              </g>
            );
          })}
          {nodes.map(node => {
            const p = positions[node.id];
            const changed = node.has_proposed_change;
            const affected = propagated.has(node.id);
            const fill = changed ? '#7c2d12' : affected ? '#78350f' : '#0f766e';
            return (
              <g key={node.id}>
                <circle cx={p.x} cy={p.y} r="46" fill={fill} stroke={changed ? '#fb923c' : affected ? '#fbbf24' : '#5eead4'} strokeWidth="3" />
                <text x={p.x} y={p.y - 5} textAnchor="middle" fill="white" fontSize="13" fontWeight="700">{node.name.slice(0, 14)}</text>
                <text x={p.x} y={p.y + 13} textAnchor="middle" fill="#dbeafe" fontSize="10">{node.role.replaceAll('_', ' ')}</text>
                <text x={p.x} y={p.y + 28} textAnchor="middle" fill="#bfdbfe" fontSize="9">{node.vendor}</text>
              </g>
            );
          })}
        </svg>
      </div>
    </div>
  );
}

function Finding({ finding }) {
  const style = severityStyle[finding.severity] || severityStyle.info;
  return (
    <div className={`rounded-xl border p-4 ${style}`}>
      <div className="flex items-center justify-between gap-3">
        <div className="font-semibold flex items-center gap-2"><AlertTriangle size={17}/>{finding.message}</div>
        <span className="text-xs font-bold uppercase">{finding.severity}</span>
      </div>
      {finding.device && <p className="text-xs mt-1 opacity-70">Scope: {finding.device}</p>}
      {finding.impact && <p className="text-sm mt-2"><strong>Impact:</strong> {finding.impact}</p>}
      {finding.recommendation && <p className="text-sm mt-2"><strong>Action:</strong> {finding.recommendation}</p>}
      {finding.evidence && <pre className="mt-2 text-xs bg-white/70 rounded-lg p-2 overflow-auto whitespace-pre-wrap">{JSON.stringify(finding.evidence, null, 2)}</pre>}
    </div>
  );
}

function Checklist({ title, icon: Icon, items = [] }) {
  if (!items.length) return null;
  return (
    <div className="rounded-xl border border-slate-200 bg-white p-4">
      <h4 className="font-semibold text-slate-900 flex items-center gap-2"><Icon size={17}/>{title}</h4>
      <ol className="mt-2 space-y-2 text-sm text-slate-700 list-decimal pl-5">
        {items.map((item, i) => <li key={i}>{item}</li>)}
      </ol>
    </div>
  );
}

export default function NetworkSafetyGraph() {
  const [devices, setDevices] = useState([emptyDevice(0), emptyDevice(1)]);
  const [result, setResult] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');

  const updateDevice = (index, value) => setDevices(prev => prev.map((d, i) => i === index ? value : d));
  const removeDevice = index => setDevices(prev => prev.filter((_, i) => i !== index));
  const addDevice = () => setDevices(prev => prev.length >= 12 ? prev : [...prev, emptyDevice(prev.length)]);

  const loadSample = () => {
    const core = `hostname CORE1
ip routing
vlan 10
 name STAFF
vlan 20
 name WIFI
vlan 30
 name VOICE
vlan 999
 name NATIVE
interface Vlan10
 ip address 10.10.10.1 255.255.255.0
interface GigabitEthernet1/0/48
 description ACCESS1
 switchport mode trunk
 switchport trunk native vlan 999
 switchport trunk allowed vlan 10,20,30,999
interface TenGigabitEthernet1/1/1
 description CORE2
 no switchport
 ip address 10.255.0.1 255.255.255.252
router ospf 10
 network 10.255.0.0 0.0.0.3 area 0`;
    const core2 = `hostname CORE2
ip routing
vlan 10
vlan 20
vlan 30
vlan 999
interface TenGigabitEthernet1/1/1
 description CORE1
 no switchport
 ip address 10.255.0.2 255.255.255.252
router ospf 10
 network 10.255.0.0 0.0.0.3 area 0`;
    const access = `hostname ACCESS1
vlan 10
vlan 20
vlan 30
vlan 999
interface GigabitEthernet1/0/48
 description CORE1
 switchport mode trunk
 switchport trunk native vlan 999
 switchport trunk allowed vlan 10,20,30,999`;
    const proposedAccess = `hostname ACCESS1
vlan 10
vlan 20
vlan 30
vlan 999
interface GigabitEthernet1/0/48
 description CORE1
 switchport mode trunk
 switchport trunk native vlan 1
 switchport trunk allowed vlan 10,20,999`;
    setDevices([
      { name: 'CORE1', vendor: 'cisco_iosxe', config_text: core, proposed_config: '', neighbor_text: 'Device ID: ACCESS1\nInterface: GigabitEthernet1/0/48, Port ID: GigabitEthernet1/0/48\nDevice ID: CORE2\nInterface: TenGigabitEthernet1/1/1, Port ID: TenGigabitEthernet1/1/1' },
      { name: 'CORE2', vendor: 'cisco_iosxe', config_text: core2, proposed_config: '', neighbor_text: 'Device ID: CORE1\nInterface: TenGigabitEthernet1/1/1, Port ID: TenGigabitEthernet1/1/1' },
      { name: 'ACCESS1', vendor: 'cisco_ios', config_text: access, proposed_config: proposedAccess, neighbor_text: 'Device ID: CORE1\nInterface: GigabitEthernet1/0/48, Port ID: GigabitEthernet1/0/48' },
    ]);
    setResult(null);
    setError('');
  };

  const run = async () => {
    setError('');
    setResult(null);
    if (devices.length < 2 || devices.some(d => !d.config_text.trim())) {
      setError('Provide at least two devices and a current sanitized config for each device.');
      return;
    }
    setLoading(true);
    try {
      const response = await axios.post(`${API_URL}/api/v1/network-graph`, { devices });
      setResult(response.data);
    } catch (err) {
      setError(err.response?.data?.detail || err.message || 'Network Safety Graph analysis failed.');
    } finally {
      setLoading(false);
    }
  };

  const downloadPassport = () => {
    if (!result) return;
    const blob = new Blob([JSON.stringify(result, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `schoolnet-network-safety-graph-${new Date().toISOString().replace(/[:.]/g, '-')}.json`;
    a.click();
    URL.revokeObjectURL(url);
  };

  return (
    <div className="space-y-5">
      <div className="rounded-2xl border border-indigo-200 bg-gradient-to-r from-indigo-50 via-white to-cyan-50 p-5">
        <div className="flex flex-col lg:flex-row lg:items-start lg:justify-between gap-4">
          <div>
            <div className="flex items-center gap-2 text-indigo-800 font-bold"><Network size={21}/> NETWORK SAFETY GRAPH</div>
            <h3 className="text-xl font-bold text-slate-950 mt-1">Peer-aware topology inference and network-wide change pre-flight</h3>
            <p className="text-sm text-slate-600 mt-2 max-w-3xl">Supply multiple sanitized configurations. Add read-only CDP/LLDP evidence when available. SchoolNet infers relationships, gateways, transit links, routing dependencies and possible single points, then evaluates proposed changes across device boundaries.</p>
          </div>
          <div className="flex flex-wrap gap-2">
            <button onClick={loadSample} className="btn secondary"><FlaskConical size={17}/> Load safety demo</button>
            <button onClick={addDevice} disabled={devices.length >= 12} className="btn secondary"><Plus size={17}/> Add device</button>
          </div>
        </div>
        <div className="grid grid-cols-2 lg:grid-cols-4 gap-3 mt-4 text-sm">
          <div className="rounded-xl bg-white border border-slate-200 p-3"><strong>Topology inference</strong><p className="text-slate-500 mt-1">Config + neighbor evidence</p></div>
          <div className="rounded-xl bg-white border border-slate-200 p-3"><strong>Cross-device invariants</strong><p className="text-slate-500 mt-1">Trunks · native VLAN · transit</p></div>
          <div className="rounded-xl bg-white border border-slate-200 p-3"><strong>Impact propagation</strong><p className="text-slate-500 mt-1">Peer and second-hop exposure</p></div>
          <div className="rounded-xl bg-white border border-slate-200 p-3"><strong>No auto-push</strong><p className="text-slate-500 mt-1">Review-first safety system</p></div>
        </div>
      </div>

      <div className="grid grid-cols-1 2xl:grid-cols-2 gap-4">
        {devices.map((device, index) => <DeviceEditor key={index} device={device} index={index} onChange={updateDevice} onRemove={removeDevice} removable={devices.length > 2} />)}
      </div>

      <div className="flex flex-wrap items-center gap-3">
        <button onClick={run} disabled={loading} className="btn">
          {loading ? <Loader2 size={18} className="animate-spin"/> : <Waypoints size={18}/>} {loading ? 'Building safety graph...' : 'Build Network Safety Graph'}
        </button>
        <span className="text-xs text-slate-500">2–50 devices supported by API · UI editor optimized for up to 12 per review</span>
      </div>

      {error && <div className="rounded-xl border border-red-300 bg-red-50 p-4 text-red-800 flex gap-2"><ShieldAlert size={20}/><span>{error}</span></div>}

      {result && (
        <div className="space-y-5">
          <div className="grid grid-cols-2 lg:grid-cols-5 gap-3">
            <div className="rounded-xl border border-slate-200 bg-white p-4"><p className="text-xs uppercase font-bold text-slate-500">Network risk</p><p className="text-2xl font-bold text-slate-950 mt-1">{result.network_risk_score}/100</p><p className="text-xs text-slate-500 uppercase">{result.network_risk_label}</p></div>
            <div className={`rounded-xl border p-4 ${gateStyle[result.network_change_gate?.status] || gateStyle.REVIEW}`}><p className="text-xs uppercase font-bold">Change gate</p><p className="text-2xl font-bold mt-1">{result.network_change_gate?.status}</p><p className="text-xs mt-1">{result.network_change_gate?.reason}</p></div>
            <div className="rounded-xl border border-slate-200 bg-white p-4"><p className="text-xs uppercase font-bold text-slate-500">Devices</p><p className="text-2xl font-bold text-slate-950 mt-1">{result.coverage?.device_count}</p><p className="text-xs text-slate-500">{result.coverage?.devices_with_proposed_changes} changed</p></div>
            <div className="rounded-xl border border-slate-200 bg-white p-4"><p className="text-xs uppercase font-bold text-slate-500">Relationships</p><p className="text-2xl font-bold text-slate-950 mt-1">{result.coverage?.inferred_relationships}</p><p className="text-xs text-slate-500">{result.coverage?.relationships_with_interface_context} with interface context</p></div>
            <div className="rounded-xl border border-slate-200 bg-white p-4"><p className="text-xs uppercase font-bold text-slate-500">Inference quality</p><p className="text-2xl font-bold text-slate-950 mt-1 capitalize">{result.topology?.inference_quality}</p><p className="text-xs text-slate-500">avg {Math.round((result.topology?.average_edge_confidence || 0) * 100)}% link confidence</p></div>
          </div>

          <TopologyGraph nodes={result.topology?.nodes || []} edges={result.topology?.edges || []} propagation={result.impact_propagation || []} />

          <div className="grid grid-cols-1 xl:grid-cols-2 gap-4">
            <div className="rounded-2xl border border-slate-200 bg-white overflow-hidden">
              <div className="px-4 py-3 bg-slate-50 border-b border-slate-200"><h3 className="font-semibold flex items-center gap-2"><Cable size={18}/> Inferred relationships</h3></div>
              <div className="divide-y divide-slate-100">
                {(result.topology?.edges || []).length === 0 && <p className="p-4 text-sm text-slate-500">No relationships inferred. Add CDP/LLDP evidence, peer descriptions, or routed transit configuration.</p>}
                {(result.topology?.edges || []).map(edge => (
                  <div key={edge.id} className="p-4 text-sm">
                    <div className="font-semibold text-slate-900">{edge.source_name} ↔ {edge.target_name}</div>
                    <div className="text-slate-500 mt-1">{edge.kind.replaceAll('_', ' ')} · {Math.round(edge.confidence * 100)}% confidence {edge.network ? `· ${edge.network}` : ''}</div>
                    {(edge.source_interface || edge.target_interface) && <div className="font-mono text-xs text-slate-600 mt-1">{edge.source_interface || '?'} ↔ {edge.target_interface || '?'}</div>}
                    <div className="text-xs text-slate-400 mt-1">{edge.evidence}</div>
                  </div>
                ))}
              </div>
            </div>

            <div className="rounded-2xl border border-slate-200 bg-white overflow-hidden">
              <div className="px-4 py-3 bg-slate-50 border-b border-slate-200"><h3 className="font-semibold flex items-center gap-2"><ServerCog size={18}/> Device roles & services</h3></div>
              <div className="divide-y divide-slate-100">
                {(result.topology?.nodes || []).map(node => (
                  <div key={node.id} className="p-4 flex items-start justify-between gap-4 text-sm">
                    <div><div className="font-semibold text-slate-900">{node.name}</div><div className="text-slate-500">{node.vendor_name} · {node.role.replaceAll('_', ' ')}</div></div>
                    <div className="text-right text-xs text-slate-500"><div>{node.trunk_count} trunks · degree {node.degree}</div><div>{node.gateway_vlans?.length || 0} gateway VLANs · {(node.routing_protocols || []).join(', ') || 'no routing protocol detected'}</div></div>
                  </div>
                ))}
              </div>
            </div>
          </div>

          {(result.cross_device_change_findings?.length > 0 || result.current_findings?.length > 0) && (
            <div className="space-y-3">
              <h3 className="font-bold text-slate-950 flex items-center gap-2"><ShieldAlert size={19}/> Network-level findings</h3>
              {result.cross_device_change_findings?.map((finding, i) => <Finding key={`cross-${i}`} finding={finding} />)}
              {result.current_findings?.map((finding, i) => <Finding key={`current-${i}`} finding={finding} />)}
            </div>
          )}

          {result.device_changes?.length > 0 && (
            <div className="rounded-2xl border border-slate-200 bg-white overflow-hidden">
              <div className="px-4 py-3 bg-slate-50 border-b border-slate-200"><h3 className="font-semibold flex items-center gap-2"><GitBranch size={18}/> Device change wave</h3></div>
              <div className="divide-y divide-slate-100">
                {result.device_changes.map(change => (
                  <div key={change.device_id} className="p-4">
                    <div className="flex flex-wrap items-center gap-2"><strong>{change.device}</strong><span className={`text-xs font-bold rounded-full border px-2 py-1 ${gateStyle[change.change_gate?.status] || gateStyle.REVIEW}`}>{change.change_gate?.status}</span><span className="text-xs text-slate-500">risk {change.risk_score}/100 · {change.risk_label}</span></div>
                    <p className="text-sm text-slate-600 mt-2">Affected domains: {(change.affected_domains || []).join(', ') || 'none detected'}</p>
                    {change.high_risk_events?.length > 0 && <div className="mt-2 text-xs text-slate-600">High-risk evidence: {change.high_risk_events.map(e => e.message).join(' · ')}</div>}
                  </div>
                ))}
              </div>
            </div>
          )}

          {result.impact_propagation?.length > 0 && (
            <div className="rounded-2xl border border-amber-200 bg-amber-50 p-4">
              <h3 className="font-semibold text-amber-950 flex items-center gap-2"><Route size={18}/> Potential impact propagation</h3>
              <div className="grid grid-cols-1 md:grid-cols-2 gap-2 mt-3">
                {result.impact_propagation.map((item, i) => <div key={i} className="rounded-lg bg-white border border-amber-200 p-3 text-sm"><strong>{item.origin_device}</strong> → <strong>{item.device}</strong><div className="text-xs text-slate-500 mt-1">{item.reason} · {item.confidence} confidence</div></div>)}
              </div>
            </div>
          )}

          <div className="grid grid-cols-1 xl:grid-cols-2 gap-4">
            <Checklist title="Network pre-change contract" icon={ShieldCheck} items={result.network_pre_change_contract} />
            <Checklist title="Post-change proof" icon={Activity} items={result.network_post_change_proof} />
          </div>

          <div className="rounded-2xl border border-slate-200 bg-slate-50 p-4">
            <div className="flex flex-col md:flex-row md:items-center md:justify-between gap-3">
              <div><h3 className="font-semibold text-slate-900 flex items-center gap-2"><CircleDot size={17}/> Evidence boundary</h3><p className="text-sm text-slate-600 mt-1">This is an inferred safety graph, not a packet-level digital twin. Verify low-confidence relationships and runtime state before production decisions.</p></div>
              <button onClick={downloadPassport} className="btn secondary"><Download size={17}/> Export Network Passport</button>
            </div>
            <ul className="mt-3 text-xs text-slate-500 list-disc pl-5 space-y-1">{result.limitations?.map((item, i) => <li key={i}>{item}</li>)}</ul>
          </div>
        </div>
      )}
    </div>
  );
}
