import React, { useEffect, useState } from 'react';
import axios from 'axios';
import { LockKeyhole, ServerCog } from 'lucide-react';

const API_URL = import.meta.env.VITE_API_URL || '';

export default function OperationalPolicyBanner() {
  const [policy, setPolicy] = useState(null);

  useEffect(() => {
    let active = true;
    axios.get(`${API_URL}/api/v1/runtime-policy`)
      .then(response => { if (active) setPolicy(response.data); })
      .catch(() => {});
    return () => { active = false; };
  }, []);

  if (!policy) return null;
  const resolver = policy.default_dns_server || 'container/system resolver';
  const live = policy.live_ssh_enabled ? 'enabled' : 'disabled';
  const https = policy.https_required_for_live_credentials ? 'HTTPS required' : 'HTTPS gate disabled';

  return (
    <div className="bg-slate-50 border border-slate-200 rounded-xl p-4 mb-5 flex flex-col md:flex-row md:items-center gap-3 md:gap-6 text-sm text-slate-700">
      <div className="flex items-center gap-2"><ServerCog size={18}/><strong>Resolver:</strong><span className="font-mono">{resolver}</span></div>
      <div className="flex items-center gap-2"><LockKeyhole size={18}/><strong>Live SSH:</strong><span>{live} · {https}</span></div>
      <div className="text-xs text-slate-500">HTTP/TLS assurance: {policy.auto_application_probe_default ? 'automatic' : 'manual'}</div>
    </div>
  );
}
