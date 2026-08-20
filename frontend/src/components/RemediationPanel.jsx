import React, { useState } from 'react';
import { Wand2, Download, Copy, CheckCircle, AlertCircle, ShieldCheck, RotateCcw, ClipboardCheck, Activity } from 'lucide-react';
import axios from 'axios';
import { OFFLINE_VENDORS } from '../vendorCatalog';

const API_URL = import.meta.env.VITE_API_URL || '';

function ListBlock({ title, items, icon: Icon }) {
  if (!items?.length) return null;
  return (
    <div className="rounded-xl border border-slate-200 bg-slate-50 p-4">
      <p className="font-semibold text-slate-900 flex items-center gap-2"><Icon size={17}/>{title}</p>
      <ol className="mt-2 list-decimal pl-5 space-y-1 text-sm text-slate-700">
        {items.map((item, idx) => <li key={idx}>{item}</li>)}
      </ol>
    </div>
  );
}

export default function RemediationPanel() {
  const [configText, setConfigText] = useState('');
  const [vendor, setVendor] = useState('auto');
  const [result, setResult] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);
  const [copied, setCopied] = useState(false);

  const generatePlan = async () => {
    if (!configText.trim()) {
      setError('Paste a sanitized configuration first.');
      return;
    }
    setLoading(true);
    setError(null);
    try {
      const validateRes = await axios.post(`${API_URL}/api/v1/validate`, { config_text: configText, vendor });
      setResult(validateRes.data);
    } catch (err) {
      setError(err.response?.data?.detail || 'Failed to generate the review plan.');
    } finally {
      setLoading(false);
    }
  };

  const planText = () => {
    if (!result) return '';
    const lines = [
      `# SchoolNet Safety-First Change Plan`,
      `Device: ${result.hostname || 'unknown'}`,
      `Platform: ${result.vendor || 'unknown'}`,
      `Risk: ${result.executive_summary?.risk_label || 'unknown'} (${result.executive_summary?.risk_score ?? 0}/100)`,
      '',
      'IMPORTANT: This is a review plan, not an auto-deployment script. Validate vendor syntax and use a maintenance window/OOB access for high-impact changes.',
      '',
    ];
    (result.findings || []).forEach((finding, idx) => {
      lines.push(`## ${idx + 1}. ${String(finding.severity || 'info').toUpperCase()} — ${finding.message}`);
      if (finding.impact) lines.push(`Impact: ${finding.impact}`);
      lines.push(`Recommendation: ${finding.remediation || ''}`);
      if (finding.evidence) lines.push(`Evidence: ${finding.evidence}`);
      const sections = [
        ['Pre-change checks', finding.pre_checks],
        ['Controlled change plan', finding.change_plan],
        ['Rollback', finding.rollback],
        ['Post-change validation', finding.post_checks],
      ];
      sections.forEach(([title, items]) => {
        if (items?.length) {
          lines.push(`${title}:`);
          items.forEach((item, i) => lines.push(`  ${i + 1}. ${item}`));
        }
      });
      lines.push('');
    });
    return lines.join('\n');
  };

  const copyPlan = async () => {
    await navigator.clipboard.writeText(planText());
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const downloadPlan = () => {
    const blob = new Blob([planText()], { type: 'text/markdown' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `${result?.hostname || 'network-device'}_safe_change_plan.md`;
    a.click();
    URL.revokeObjectURL(url);
  };

  return (
    <div className="max-w-6xl mx-auto space-y-6">
      <div className="flex items-center gap-3">
        <ShieldCheck className="text-school-600" size={28} />
        <div>
          <h1 className="text-2xl font-bold text-slate-950">Safety-First Change Plan</h1>
          <p className="text-slate-500">Turn detected risks into pre-checks, staged changes, rollback criteria, and post-change validation.</p>
        </div>
      </div>

      <div className="bg-amber-50 border border-amber-200 rounded-xl p-4 text-sm text-amber-900 flex gap-3">
        <AlertCircle size={20} className="flex-none" />
        <p><strong>No automatic device changes.</strong> SchoolNet intentionally produces a review-first plan. Vendor syntax, topology dependencies, redundancy, maintenance window, and out-of-band recovery must be validated by an engineer before production changes.</p>
      </div>

      <div className="bg-white rounded-2xl border border-slate-200 overflow-hidden shadow-sm">
        <div className="p-4 border-b border-slate-100 flex flex-col lg:flex-row gap-3 lg:items-center lg:justify-between">
          <select value={vendor} onChange={(e) => setVendor(e.target.value)} className="bg-slate-50 border border-slate-300 rounded-lg px-3 py-2.5 text-sm lg:min-w-[360px]">
            {OFFLINE_VENDORS.map(item => <option key={item.id} value={item.id}>{item.name}</option>)}
          </select>
          <button onClick={generatePlan} disabled={loading || !configText.trim()} className="px-4 py-2.5 bg-school-600 text-white rounded-lg hover:bg-school-700 disabled:opacity-50 flex items-center justify-center gap-2 text-sm font-semibold">
            <Wand2 size={17}/>{loading ? 'Analyzing...' : 'Build Safe Change Plan'}
          </button>
        </div>
        <textarea
          value={configText}
          onChange={(e) => setConfigText(e.target.value)}
          placeholder="Paste a sanitized configuration. SchoolNet will analyze it and build a non-executable engineering change plan."
          className="w-full h-72 p-4 font-mono text-sm bg-slate-950 text-emerald-300 resize-none focus:outline-none"
          spellCheck={false}
        />
      </div>

      {error && <div className="bg-red-50 border border-red-200 rounded-xl p-4 flex items-center gap-3 text-red-700"><AlertCircle size={20}/><p>{error}</p></div>}

      {result && (
        <div className="space-y-5">
          <div className="bg-white rounded-2xl border border-slate-200 p-6 shadow-sm flex flex-col lg:flex-row lg:items-center lg:justify-between gap-4">
            <div>
              <p className="text-xs font-bold uppercase tracking-wider text-slate-500">Change Review</p>
              <h2 className="text-xl font-bold text-slate-950 mt-1">{result.hostname || 'Unknown Device'} · {result.vendor}</h2>
              <p className="text-sm text-slate-600 mt-1">{result.summary.total} finding(s) · risk {result.executive_summary?.risk_label} ({result.executive_summary?.risk_score}/100)</p>
            </div>
            <div className="flex gap-2">
              <button onClick={copyPlan} className="flex items-center gap-2 px-3 py-2 text-sm bg-slate-100 hover:bg-slate-200 rounded-lg">{copied ? <CheckCircle size={16} className="text-emerald-600"/> : <Copy size={16}/>} {copied ? 'Copied' : 'Copy Plan'}</button>
              <button onClick={downloadPlan} className="flex items-center gap-2 px-3 py-2 text-sm bg-school-600 text-white hover:bg-school-700 rounded-lg"><Download size={16}/> Download</button>
            </div>
          </div>

          {(result.findings || []).map((finding, idx) => (
            <div key={idx} className="bg-white rounded-2xl border border-slate-200 p-5 shadow-sm">
              <div className="flex items-start justify-between gap-3">
                <div>
                  <span className="text-xs font-bold uppercase tracking-wider text-slate-500">{finding.severity} · {finding.check_type}</span>
                  <h3 className="font-bold text-slate-950 mt-1">{finding.message}</h3>
                  {finding.impact && <p className="text-sm text-slate-600 mt-1">{finding.impact}</p>}
                </div>
                <span className="text-xs text-slate-500 whitespace-nowrap">{finding.confidence || 'medium'} confidence</span>
              </div>
              <div className="mt-4 bg-blue-50 border border-blue-200 rounded-xl p-4 text-sm text-blue-900"><strong>Recommendation:</strong> {finding.remediation}</div>
              <div className="grid grid-cols-1 lg:grid-cols-2 gap-3 mt-4">
                <ListBlock title="Pre-change checks" items={finding.pre_checks} icon={ClipboardCheck}/>
                <ListBlock title="Controlled change" items={finding.change_plan} icon={ShieldCheck}/>
                <ListBlock title="Rollback" items={finding.rollback} icon={RotateCcw}/>
                <ListBlock title="Post-change validation" items={finding.post_checks} icon={Activity}/>
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
