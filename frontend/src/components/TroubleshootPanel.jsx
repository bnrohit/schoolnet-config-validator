import React, { useEffect, useMemo, useState } from 'react';
import { Terminal, Play, Loader2, AlertCircle, CheckCircle, Server, Lock, ShieldCheck, KeyRound, Clock3 } from 'lucide-react';
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
  const isHttps = typeof window !== 'undefined' && window.location.protocol === 'https:';
  const [host, setHost] = useState('');
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [deviceType, setDeviceType] = useState('cisco_ios');
  const [selectedCheck, setSelectedCheck] = useState('all');
  const [results, setResults] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);
  const [showPassword, setShowPassword] = useState(false);
  const [profiles, setProfiles] = useState([]);
  const [selectedProfile, setSelectedProfile] = useState('');
  const [bridgePolicy, setBridgePolicy] = useState(null);
  const [credentialMode, setCredentialMode] = useState(isHttps ? 'browser' : 'bridge');
  const [job, setJob] = useState(null);

  useEffect(() => {
    let active = true;
    Promise.allSettled([
      axios.get(`${API_URL}/api/v1/secure-live/profiles`),
      axios.get(`${API_URL}/api/v1/secure-live/policy`),
    ]).then(([profileResp, policyResp]) => {
      if (!active) return;
      if (profileResp.status === 'fulfilled') {
        const values = profileResp.value.data?.profiles || [];
        setProfiles(values);
        if (values.length) setSelectedProfile(values[0].id);
      }
      if (policyResp.status === 'fulfilled') setBridgePolicy(policyResp.value.data);
    });
    return () => { active = false; };
  }, []);

  useEffect(() => {
    if (!job?.job_id || !['pending', 'running'].includes(job.status)) return undefined;
    const timer = setInterval(async () => {
      try {
        const response = await axios.get(`${API_URL}/api/v1/secure-live/jobs/${job.job_id}`);
        const updated = response.data;
        setJob(updated);
        if (updated.status === 'completed' && updated.result) {
          setResults(updated.result);
          setLoading(false);
        }
        if (['failed', 'expired'].includes(updated.status)) {
          setError(updated.error || `Secure live job ${updated.status}.`);
          setLoading(false);
        }
      } catch (err) {
        setError(err.response?.data?.detail || 'Could not poll the secure live job.');
        setLoading(false);
      }
    }, 2000);
    return () => clearInterval(timer);
  }, [job?.job_id, job?.status]);

  const profile = useMemo(() => profiles.find(item => item.id === selectedProfile), [profiles, selectedProfile]);
  const allowedChecks = profile?.allowed_checks || [];
  const checkAllowedByProfile = credentialMode !== 'bridge' || !profile || allowedChecks.includes(selectedCheck);

  const runDirect = async () => {
    if (!host || !username || !password) {
      setError('Host, username, and password are required.');
      return;
    }
    setLoading(true); setError(null); setResults(null); setJob(null);
    try {
      const response = await axios.post(`${API_URL}/api/v1/troubleshoot`, {
        host, username, password, device_type: deviceType, check: selectedCheck
      });
      setResults(response.data);
    } catch (err) {
      setError(err.response?.data?.detail || 'Connection failed. Verify IP, credentials, SSH access, and live-diagnostics policy.');
    } finally {
      setPassword('');
      setLoading(false);
    }
  };

  const runProfile = async () => {
    if (!host || !selectedProfile) {
      setError('Target and server-side credential profile are required.');
      return;
    }
    if (!checkAllowedByProfile) {
      setError('This diagnostic category is not permitted by the selected credential profile.');
      return;
    }
    setLoading(true); setError(null); setResults(null); setJob(null);
    try {
      if (isHttps) {
        const response = await axios.post(`${API_URL}/api/v1/secure-live/run`, {
          profile_id: selectedProfile, target: host, check: selectedCheck
        });
        setResults(response.data);
        setLoading(false);
      } else {
        const response = await axios.post(`${API_URL}/api/v1/secure-live/jobs`, {
          profile_id: selectedProfile, target: host, check: selectedCheck
        });
        setJob(response.data);
      }
    } catch (err) {
      setError(err.response?.data?.detail || 'Secure Live Bridge request failed.');
      setLoading(false);
    }
  };

  const runTroubleshoot = credentialMode === 'browser' ? runDirect : runProfile;

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
        <p className="text-sm"><strong>Read-only policy:</strong> predefined show/display/get commands only. Configuration, save, reload, delete, and commit operations are blocked. Use dedicated least-privilege accounts.</p>
      </div>

      {!isHttps && (
        <div className="bg-amber-50 border border-amber-200 rounded-xl p-4 text-amber-950 space-y-2">
          <div className="flex items-start gap-3"><KeyRound size={20} className="flex-none mt-0.5"/><p className="text-sm"><strong>No HTTPS detected.</strong> Browser password entry is disabled. Secure Live Bridge can keep credentials only on the SchoolNet server and require terminal/SSH approval for every job.</p></div>
          <p className="text-xs text-amber-800">This protects device credentials and execution authorization, but plain HTTP still cannot protect diagnostic-result confidentiality or page integrity. Keep SchoolNet on a trusted management network and move to HTTPS when possible.</p>
        </div>
      )}

      <div className="bg-white rounded-2xl border border-slate-200 p-6 shadow-sm space-y-5">
        <div className="flex items-center justify-between gap-3 flex-wrap">
          <h2 className="text-lg font-semibold text-slate-950 flex items-center gap-2"><Server size={20}/> Connection</h2>
          <div className="flex gap-2">
            {isHttps && <button onClick={() => setCredentialMode('browser')} className={`px-3 py-2 rounded-lg text-sm border ${credentialMode === 'browser' ? 'border-school-500 bg-school-50 text-school-700' : 'border-slate-200'}`}>HTTPS credentials</button>}
            <button disabled={!profiles.length} onClick={() => setCredentialMode('bridge')} className={`px-3 py-2 rounded-lg text-sm border disabled:opacity-40 ${credentialMode === 'bridge' ? 'border-school-500 bg-school-50 text-school-700' : 'border-slate-200'}`}>Server profile</button>
          </div>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-4 gap-4">
          <div>
            <label className="block text-sm font-medium text-slate-700 mb-1">Host / IP</label>
            <input type="text" value={host} onChange={(e) => setHost(e.target.value)} placeholder="10.0.0.10" className="w-full px-3 py-2 border border-slate-300 rounded-lg focus:ring-2 focus:ring-school-500" />
          </div>

          {credentialMode === 'browser' ? <>
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
          </> : <>
            <div className="md:col-span-2">
              <label className="block text-sm font-medium text-slate-700 mb-1">Server-side credential profile</label>
              <select value={selectedProfile} onChange={(e) => setSelectedProfile(e.target.value)} className="w-full px-3 py-2 border border-slate-300 rounded-lg">
                {!profiles.length && <option value="">No profiles available</option>}
                {profiles.map(item => <option key={item.id} value={item.id}>{item.label} · {item.device_type} · {item.auth_method}</option>)}
              </select>
              {profile && <p className="text-xs text-slate-500 mt-2">Allowed targets: {profile.allowed_targets?.join(', ') || 'none'} · Host-key verification: {profile.strict_host_key ? 'strict' : 'profile default'}</p>}
            </div>
          </>}
        </div>
      </div>

      <div className="bg-white rounded-2xl border border-slate-200 p-6 shadow-sm">
        <h2 className="text-lg font-semibold text-slate-950 mb-4">Select diagnostic</h2>
        <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-4 xl:grid-cols-6 gap-3">
          {Object.entries(commandCategories).map(([key, { label, desc }]) => {
            const permitted = credentialMode !== 'bridge' || !profile || allowedChecks.includes(key);
            return (
              <button key={key} disabled={!permitted} onClick={() => setSelectedCheck(key)} className={`p-3 rounded-xl border text-left transition-all disabled:opacity-35 ${selectedCheck === key ? 'border-school-500 bg-school-50 ring-2 ring-school-200' : 'border-slate-200 hover:border-slate-300 hover:bg-slate-50'}`}>
                <p className={`font-semibold text-sm ${selectedCheck === key ? 'text-school-700' : 'text-slate-800'}`}>{label}</p>
                <p className="text-xs text-slate-500 mt-1">{desc}</p>
              </button>
            );
          })}
        </div>
        <button onClick={runTroubleshoot} disabled={loading || (credentialMode === 'bridge' && !profiles.length)} className="mt-6 w-full md:w-auto px-6 py-3 bg-school-600 text-white rounded-lg hover:bg-school-700 disabled:opacity-50 flex items-center justify-center gap-2 font-semibold">
          {loading ? <Loader2 size={18} className="animate-spin" /> : <Play size={18} />}
          {loading ? (job ? 'Waiting for approval / result...' : 'Running read-only diagnostics...') : (credentialMode === 'bridge' && !isHttps ? 'Create OOB-Approved Diagnostic Job' : 'Run Read-Only Diagnostics')}
        </button>
      </div>

      {job && ['pending', 'running'].includes(job.status) && (
        <div className="bg-blue-50 border border-blue-200 rounded-xl p-5 text-blue-950 space-y-3">
          <div className="flex items-center gap-2"><Clock3 size={20}/><strong>Secure Live job: {job.status}</strong></div>
          <p className="text-sm">No device password was sent through this browser. Approve the exact pending job from the SchoolNet host using your secure administrative connection:</p>
          <pre className="bg-slate-950 text-emerald-300 p-3 rounded-lg text-xs overflow-x-auto">{job.approval_command}</pre>
          <p className="text-xs">Job ID: {job.job_id} · Expires: {job.expires_at}</p>
        </div>
      )}

      {bridgePolicy && credentialMode === 'bridge' && !profiles.length && (
        <div className="bg-slate-50 border border-slate-200 rounded-xl p-4 text-sm text-slate-700">
          Secure Live Bridge profiles are {bridgePolicy.server_profiles_enabled ? 'enabled but none were loaded' : 'disabled'}. See <code>docs/SECURE_LIVE_BRIDGE.md</code> for server-side setup.
        </div>
      )}

      {error && <div className="bg-red-50 border border-red-200 rounded-xl p-4 flex items-start gap-3 text-red-700"><AlertCircle size={20} className="flex-none"/><div><p className="font-medium">Diagnostic error</p><p className="text-sm">{error}</p></div></div>}

      {results && (
        <div className="space-y-4">
          <div className="flex items-center justify-between gap-3 flex-wrap">
            <h2 className="text-lg font-semibold text-slate-950 flex items-center gap-2"><CheckCircle size={20} className="text-emerald-500"/> Results from {results.host}</h2>
            <span className="text-sm text-slate-500">{results.device_type} · {results.mode}</span>
          </div>
          {Array.isArray(results.results) ? results.results.map((category, i) => <CommandOutput key={i} result={category}/>) : <CommandOutput result={results.results}/>} 
        </div>
      )}
    </div>
  );
}
