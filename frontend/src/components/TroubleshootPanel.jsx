import React, { useState } from 'react';
import { Terminal, Play, Loader2, AlertCircle, CheckCircle, Server, Lock, ShieldCheck } from 'lucide-react';
import axios from 'axios';
import { LIVE_DEVICE_TYPES } from '../vendorCatalog';

const API_URL = import.meta.env.VITE_API_URL || '';

const commandCategories = {
  basic: { label: 'Basic Info', desc: 'Version, uptime, users' },
  interfaces: { label: 'Interfaces', desc: 'State, errors, descriptions' },
  vlan: { label: 'VLAN / Trunks', desc: 'Layer-2 segmentation' },
  stp: { label: 'Loop Prevention', desc: 'STP / bridge topology' },
  mac: { label: 'MAC / FDB', desc: 'Address learning' },
  arp: { label: 'ARP / Routes', desc: 'Neighbor and route state' },
  routing: { label: 'Routing', desc: 'OSPF/BGP neighbors and routes' },
  errors: { label: 'Errors / Logs', desc: 'Counters and recent events' },
  neighbors: { label: 'Neighbors', desc: 'LLDP/CDP discovery' },
  poe: { label: 'PoE', desc: 'Power state where supported' },
  security: { label: 'Security', desc: 'Read-only management/security state' },
  all: { label: 'All Read-Only Checks', desc: 'Complete safe diagnostic suite' },
};

function CommandOutput({ result }) {
  if (!result) return null;
  return (
    <div className="bg-slate-950 rounded-xl overflow-hidden border border-slate-800">
      <div className="bg-slate-900 px-4 py-2 flex items-center justify-between gap-3">
        <span className="text-xs font-mono text-slate-300">{result.category}</span>
        <span className="text-xs text-slate-500">{result.description}</span>
      </div>
      <div className="p-4 space-y-4 max-h-[32rem] overflow-y-auto">
        {result.results?.length ? result.results.map((cmd, i) => (
          <div key={i} className="space-y-2">
            <div className="flex items-center gap-2">
              <span className="text-emerald-400 font-mono text-sm">$</span>
              <span className="text-emerald-300 font-mono text-sm">{cmd.command}</span>
            </div>
            {cmd.error ? (
              <div className="text-amber-300 text-xs font-mono bg-amber-950/40 border border-amber-900 p-3 rounded">{cmd.error}</div>
            ) : (
              <pre className="text-slate-300 text-xs font-mono whitespace-pre-wrap bg-slate-900/70 p-3 rounded overflow-x-auto">{typeof cmd.raw === 'string' ? cmd.raw : JSON.stringify(cmd.raw, null, 2)}</pre>
            )}
          </div>
        )) : <p className="text-sm text-slate-500">No read-only commands are defined for this category on the selected platform.</p>}
      </div>
    </div>
  );
}

export default function TroubleshootPanel() {
  const [host, setHost] = useState('');
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [deviceType, setDeviceType] = useState('cisco_ios');
  const [selectedCheck, setSelectedCheck] = useState('all');
  const [results, setResults] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);
  const [showPassword, setShowPassword] = useState(false);

  const runTroubleshoot = async () => {
    if (!host || !username || !password) {
      setError('Host, username, and password are required.');
      return;
    }
    setLoading(true);
    setError(null);
    setResults(null);
    try {
      const response = await axios.post(`${API_URL}/api/v1/troubleshoot`, {
        host, username, password, device_type: deviceType, check: selectedCheck
      });
      setResults(response.data);
    } catch (err) {
      setError(err.response?.data?.detail || 'Connection failed. Verify IP, credentials, SSH access, and that live diagnostics are enabled.');
    } finally {
      setPassword('');
      setLoading(false);
    }
  };

  return (
    <div className="max-w-6xl mx-auto space-y-6">
      <div className="flex items-center gap-3">
        <Terminal className="text-school-600" size={28} />
        <div>
          <h1 className="text-2xl font-bold text-slate-950">Read-Only Live Diagnostics</h1>
          <p className="text-slate-500">Vendor-aware operational checks without entering configuration mode.</p>
        </div>
      </div>

      <div className="bg-emerald-50 border border-emerald-200 rounded-xl p-4 flex items-start gap-3 text-emerald-900">
        <ShieldCheck size={20} className="flex-none mt-0.5" />
        <p className="text-sm"><strong>Read-only policy:</strong> live diagnostics use predefined show/display/get commands. The backend blocks obvious configuration, save, reload, delete, and commit operations. Use a least-privilege account and HTTPS before entering credentials.</p>
      </div>

      <div className="bg-white rounded-2xl border border-slate-200 p-6 shadow-sm">
        <h2 className="text-lg font-semibold text-slate-950 mb-4 flex items-center gap-2"><Server size={20}/> Connection</h2>
        <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-4 gap-4">
          <div>
            <label className="block text-sm font-medium text-slate-700 mb-1">Host / IP</label>
            <input type="text" value={host} onChange={(e) => setHost(e.target.value)} placeholder="10.0.0.10" className="w-full px-3 py-2 border border-slate-300 rounded-lg focus:ring-2 focus:ring-school-500" />
          </div>
          <div>
            <label className="block text-sm font-medium text-slate-700 mb-1">Username</label>
            <input type="text" value={username} onChange={(e) => setUsername(e.target.value)} placeholder="readonly-ops" autoComplete="username" className="w-full px-3 py-2 border border-slate-300 rounded-lg focus:ring-2 focus:ring-school-500" />
          </div>
          <div>
            <label className="block text-sm font-medium text-slate-700 mb-1">Password</label>
            <div className="relative">
              <input type={showPassword ? 'text' : 'password'} value={password} onChange={(e) => setPassword(e.target.value)} placeholder="••••••••" autoComplete="current-password" className="w-full px-3 py-2 border border-slate-300 rounded-lg focus:ring-2 focus:ring-school-500 pr-10" />
              <button type="button" onClick={() => setShowPassword(!showPassword)} className="absolute right-3 top-1/2 -translate-y-1/2 text-slate-400 hover:text-slate-600" aria-label="Toggle password visibility"><Lock size={16}/></button>
            </div>
          </div>
          <div>
            <label className="block text-sm font-medium text-slate-700 mb-1">Platform driver</label>
            <select value={deviceType} onChange={(e) => setDeviceType(e.target.value)} className="w-full px-3 py-2 border border-slate-300 rounded-lg focus:ring-2 focus:ring-school-500">
              {LIVE_DEVICE_TYPES.map(item => <option key={item.id} value={item.id}>{item.name}</option>)}
            </select>
          </div>
        </div>
      </div>

      <div className="bg-white rounded-2xl border border-slate-200 p-6 shadow-sm">
        <h2 className="text-lg font-semibold text-slate-950 mb-4">Select diagnostic</h2>
        <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-4 xl:grid-cols-6 gap-3">
          {Object.entries(commandCategories).map(([key, { label, desc }]) => (
            <button key={key} onClick={() => setSelectedCheck(key)} className={`p-3 rounded-xl border text-left transition-all ${selectedCheck === key ? 'border-school-500 bg-school-50 ring-2 ring-school-200' : 'border-slate-200 hover:border-slate-300 hover:bg-slate-50'}`}>
              <p className={`font-semibold text-sm ${selectedCheck === key ? 'text-school-700' : 'text-slate-800'}`}>{label}</p>
              <p className="text-xs text-slate-500 mt-1">{desc}</p>
            </button>
          ))}
        </div>
        <button onClick={runTroubleshoot} disabled={loading} className="mt-6 w-full md:w-auto px-6 py-3 bg-school-600 text-white rounded-lg hover:bg-school-700 disabled:opacity-50 flex items-center justify-center gap-2 font-semibold">
          {loading ? <Loader2 size={18} className="animate-spin" /> : <Play size={18} />}
          {loading ? 'Running read-only diagnostics...' : 'Run Read-Only Diagnostics'}
        </button>
      </div>

      {error && <div className="bg-red-50 border border-red-200 rounded-xl p-4 flex items-start gap-3 text-red-700"><AlertCircle size={20} className="flex-none"/><div><p className="font-medium">Diagnostic error</p><p className="text-sm">{error}</p></div></div>}

      {results && (
        <div className="space-y-4">
          <div className="flex items-center justify-between gap-3 flex-wrap">
            <h2 className="text-lg font-semibold text-slate-950 flex items-center gap-2"><CheckCircle size={20} className="text-emerald-500"/> Results from {results.host}</h2>
            <span className="text-sm text-slate-500">{results.device_type}</span>
          </div>
          {Array.isArray(results.results) ? results.results.map((category, i) => <CommandOutput key={i} result={category}/>) : <CommandOutput result={results.results}/>} 
        </div>
      )}
    </div>
  );
}
