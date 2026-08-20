import React, { useEffect, useState } from 'react';
import axios from 'axios';
import { Clock3, KeyRound, LockKeyhole, Route, ServerCog } from 'lucide-react';

const API_URL = import.meta.env.VITE_API_URL || '';

export default function OperationalPolicyBanner() {
  const [policy, setPolicy] = useState(null);
  const [secureLive, setSecureLive] = useState(null);

  useEffect(() => {
    let active = true;
    Promise.allSettled([
      axios.get(`${API_URL}/api/v1/runtime-policy`),
      axios.get(`${API_URL}/api/v1/secure-live/policy`),
    ]).then(([runtimeResp, secureResp]) => {
      if (!active) return;
      if (runtimeResp.status === 'fulfilled') setPolicy(runtimeResp.value.data);
      if (secureResp.status === 'fulfilled') setSecureLive(secureResp.value.data);
    });
    return () => { active = false; };
  }, []);

  if (!policy) return null;
  const resolver = policy.default_dns_server || 'container/system resolver';
  const live = policy.live_ssh_enabled ? 'enabled' : 'disabled';
  const https = policy.https_required_for_live_credentials ? 'HTTPS required' : 'HTTPS gate disabled';
  const history = policy.diagnostic_history?.enabled ? `enabled · ${policy.diagnostic_history.retention_runs} runs` : 'disabled';
  const bridge = secureLive?.server_profiles_enabled
    ? `${secureLive.profile_count || 0} profile(s) · ${secureLive.http_oob_enabled ? 'HTTP OOB ready' : 'HTTPS only'}`
    : 'disabled';

  return (
    <div className="bg-slate-50 border border-slate-200 rounded-xl p-4 mb-5 flex flex-col 2xl:flex-row 2xl:items-center gap-3 2xl:gap-6 text-sm text-slate-700">
      <div className="flex items-center gap-2"><ServerCog size={18}/><strong>Resolver:</strong><span className="font-mono">{resolver}</span></div>
      <div className="flex items-center gap-2"><LockKeyhole size={18}/><strong>Live SSH:</strong><span>{live} · {https}</span></div>
      <div className="flex items-center gap-2"><KeyRound size={18}/><strong>Secure Bridge:</strong><span>{bridge}</span></div>
      <div className="flex items-center gap-2"><Route size={18}/><strong>Path:</strong><span>≤ {policy.path_intelligence?.max_samples_per_hop || 10} samples/hop</span></div>
      <div className="flex items-center gap-2"><Clock3 size={18}/><strong>History:</strong><span>{history}</span></div>
      <div className="text-xs text-slate-500">HTTP/TLS assurance: {policy.auto_application_probe_default ? 'automatic' : 'manual'}</div>
    </div>
  );
}
