import React, { useState, useCallback } from 'react';
import { useDropzone } from 'react-dropzone';
import {
  Upload, AlertCircle, CheckCircle, AlertTriangle, Info, ChevronDown,
  ChevronUp, Download, Shield, Loader2, FileText, Sparkles, LockKeyhole,
  RotateCcw, ClipboardCheck, Activity
} from 'lucide-react';
import axios from 'axios';
import { OFFLINE_VENDORS } from '../vendorCatalog';

const API_URL = import.meta.env.VITE_API_URL || '';

const severityConfig = {
  critical: { icon: AlertCircle, color: 'text-red-700', bg: 'bg-red-50', border: 'border-red-500', label: 'Critical' },
  high: { icon: AlertTriangle, color: 'text-orange-700', bg: 'bg-orange-50', border: 'border-orange-500', label: 'High' },
  medium: { icon: AlertTriangle, color: 'text-amber-700', bg: 'bg-amber-50', border: 'border-amber-400', label: 'Medium' },
  low: { icon: Info, color: 'text-blue-700', bg: 'bg-blue-50', border: 'border-blue-400', label: 'Low' },
  info: { icon: Info, color: 'text-slate-600', bg: 'bg-slate-50', border: 'border-slate-400', label: 'Info' },
};

function StepList({ title, icon: Icon, items, tone = 'slate' }) {
  if (!items?.length) return null;
  const tones = {
    slate: 'border-slate-200 bg-slate-50 text-slate-700',
    blue: 'border-blue-200 bg-blue-50 text-blue-800',
    amber: 'border-amber-200 bg-amber-50 text-amber-800',
    green: 'border-emerald-200 bg-emerald-50 text-emerald-800',
  };
  return (
    <div className={`rounded-xl border p-4 ${tones[tone] || tones.slate}`}>
      <p className="text-xs font-bold uppercase tracking-wider flex items-center gap-2 mb-2">
        <Icon size={15} /> {title}
      </p>
      <ol className="space-y-1.5 text-sm list-decimal pl-5">
        {items.map((item, idx) => <li key={idx}>{item}</li>)}
      </ol>
    </div>
  );
}

function FindingCard({ finding, index }) {
  const [expanded, setExpanded] = useState(false);
  const config = severityConfig[finding.severity] || severityConfig.info;
  const Icon = config.icon;

  return (
    <div className={`rounded-xl border border-slate-200 border-l-4 ${config.border} ${config.bg} overflow-hidden shadow-sm`}>
      <button onClick={() => setExpanded(!expanded)} className="w-full p-4 flex items-start gap-3 text-left hover:bg-white/60 transition-colors">
        <Icon size={20} className={`${config.color} mt-0.5 flex-shrink-0`} />
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2 flex-wrap">
            <span className={`text-xs font-bold px-2 py-0.5 rounded-md ${config.color} bg-white/80`}>{config.label}</span>
            <span className="text-xs text-slate-500">#{index + 1}</span>
            {finding.confidence && <span className="text-xs text-slate-500 bg-white/70 px-2 py-0.5 rounded-md">{finding.confidence} confidence</span>}
            {finding.interface && <span className="text-xs font-mono bg-slate-900 text-white px-2 py-0.5 rounded">{finding.interface}</span>}
          </div>
          <p className="mt-1.5 font-semibold text-slate-950">{finding.message}</p>
          {finding.impact && <p className="text-sm text-slate-600 mt-1">{finding.impact}</p>}
        </div>
        {expanded ? <ChevronUp size={18} className="text-slate-400" /> : <ChevronDown size={18} className="text-slate-400" />}
      </button>

      {expanded && (
        <div className="px-4 pb-4 pt-0 space-y-3">
          <div className="bg-white rounded-xl border border-slate-200 p-4">
            <p className="text-xs font-bold text-slate-500 uppercase tracking-wider">Engineer Recommendation</p>
            <p className="text-sm text-slate-700 mt-1.5">{finding.remediation}</p>
            {finding.evidence && (
              <div className="mt-3">
                <p className="text-xs font-bold text-slate-500 uppercase tracking-wider">Evidence</p>
                <pre className="mt-1 text-xs bg-slate-950 text-emerald-300 p-3 rounded-lg overflow-x-auto whitespace-pre-wrap">{finding.evidence}</pre>
              </div>
            )}
          </div>

          <div className="grid grid-cols-1 lg:grid-cols-2 gap-3">
            <StepList title="Pre-change checks" icon={ClipboardCheck} items={finding.pre_checks} tone="blue" />
            <StepList title="Controlled change plan" icon={Shield} items={finding.change_plan} tone="amber" />
            <StepList title="Rollback path" icon={RotateCcw} items={finding.rollback} tone="slate" />
            <StepList title="Post-change validation" icon={Activity} items={finding.post_checks} tone="green" />
          </div>

          {finding.raw_config && (
            <div className="bg-white rounded-xl border border-slate-200 p-4">
              <p className="text-xs font-bold text-slate-500 uppercase tracking-wider">Sanitized config context</p>
              <pre className="mt-1 text-xs bg-slate-950 text-emerald-300 p-3 rounded-lg overflow-x-auto">{finding.raw_config}</pre>
            </div>
          )}

          <div className="flex items-center gap-2 text-xs text-slate-500 px-1">
            <LockKeyhole size={14} />
            Review-first only. SchoolNet does not automatically apply this finding to the device.
          </div>
        </div>
      )}
    </div>
  );
}

function SummaryCard({ label, count, color }) {
  return (
    <div className="bg-white rounded-xl border border-slate-200 p-4 text-center shadow-sm">
      <p className={`text-2xl font-bold ${color}`}>{count}</p>
      <p className="text-xs text-slate-500 mt-1">{label}</p>
    </div>
  );
}

export default function ConfigValidator() {
  const [configText, setConfigText] = useState('');
  const [vendor, setVendor] = useState('auto');
  const [result, setResult] = useState(null);
  const [loading, setLoading] = useState(false);
  const [sampleLoading, setSampleLoading] = useState(false);
  const [error, setError] = useState(null);
  const [activeFilter, setActiveFilter] = useState('all');

  const onDrop = useCallback((acceptedFiles) => {
    const file = acceptedFiles[0];
    if (!file) return;
    const reader = new FileReader();
    reader.onload = (e) => {
      setConfigText(e.target.result);
      setResult(null);
      setError(null);
    };
    reader.readAsText(file);
  }, []);

  const { getRootProps, getInputProps, isDragActive } = useDropzone({
    onDrop,
    accept: { 'text/plain': ['.txt', '.cfg', '.config', '.conf'] },
    multiple: false,
  });

  const loadSample = async () => {
    setSampleLoading(true);
    setError(null);
    try {
      const response = await axios.get(`${API_URL}/api/v1/examples`);
      setConfigText(response.data.broken_config || '');
      setResult(null);
      setVendor('auto');
    } catch (err) {
      setError('Could not load the included sample configuration. Verify the backend/API proxy is healthy.');
    } finally {
      setSampleLoading(false);
    }
  };

  const sanitize = async () => {
    if (!configText.trim()) {
      setError('Paste or upload a configuration before sanitizing.');
      return;
    }
    try {
      const response = await axios.post(`${API_URL}/api/v1/sanitize`, { config_text: configText, vendor });
      setConfigText(response.data.sanitized_config_text);
      setError(response.data.changed ? null : 'No obvious secrets were found by the built-in sanitizer. Review the text manually before sharing it.');
    } catch (err) {
      setError(err.response?.data?.detail || 'Sanitization failed.');
    }
  };

  const validate = async () => {
    if (!configText.trim()) {
      setError('Paste or upload a configuration first.');
      return;
    }
    setLoading(true);
    setError(null);
    try {
      const response = await axios.post(`${API_URL}/api/v1/validate`, { config_text: configText, vendor });
      setResult(response.data);
      setActiveFilter('all');
    } catch (err) {
      setError(err.response?.data?.detail || 'Validation failed. Verify the API is reachable.');
    } finally {
      setLoading(false);
    }
  };

  const downloadJsonReport = () => {
    if (!result) return;
    const blob = new Blob([JSON.stringify(result, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `${result.hostname || 'network-device'}_schoolnet_report.json`;
    a.click();
    URL.revokeObjectURL(url);
  };

  const downloadMarkdownReport = async () => {
    if (!result) return;
    try {
      const response = await axios.post(`${API_URL}/api/v1/report/markdown`, { result }, { responseType: 'text' });
      const blob = new Blob([response.data], { type: 'text/markdown' });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `${result.hostname || 'network-device'}_schoolnet_report.md`;
      a.click();
      URL.revokeObjectURL(url);
    } catch (err) {
      setError('Markdown report generation failed.');
    }
  };

  const filteredFindings = result?.findings?.filter(f => activeFilter === 'all' || f.severity === activeFilter) || [];
  const risk = result?.executive_summary;
  const detectedVendor = result?.vendor || '';
  const parserConfidence = result?.analysis?.parser_confidence;

  return (
    <div className="max-w-6xl mx-auto space-y-6">
      <div className="flex items-center gap-3">
        <Shield className="text-school-600" size={28} />
        <div>
          <h1 className="text-2xl font-bold text-slate-950">Universal Configuration Review</h1>
          <p className="text-slate-500">Auto-detect the platform, identify evidence-backed risks, and build a safer change plan.</p>
        </div>
      </div>

      <div className="bg-blue-50 border border-blue-200 rounded-xl p-4 flex items-start gap-3">
        <Sparkles size={20} className="text-blue-600 flex-none mt-0.5" />
        <div>
          <p className="font-bold text-blue-950">Safety-first workflow</p>
          <p className="text-sm text-blue-800 mt-1">
            Use <strong>Auto-detect</strong> for most switches, routers, and network appliances. The engine reports only evidence it can support and includes pre-checks, rollback, and post-change validation for high-impact findings. It does not auto-push configuration changes.
          </p>
        </div>
      </div>

      <div className="bg-white rounded-2xl border border-slate-200 overflow-hidden shadow-sm">
        <div className="p-4 border-b border-slate-100 space-y-3">
          <label className="block text-xs font-bold uppercase tracking-wider text-slate-500">Platform / operating system</label>
          <div className="flex flex-col xl:flex-row gap-3 xl:items-center xl:justify-between">
            <select value={vendor} onChange={(e) => setVendor(e.target.value)} className="bg-slate-50 border border-slate-300 rounded-lg px-3 py-2.5 text-sm min-w-0 xl:min-w-[360px]">
              {OFFLINE_VENDORS.map(item => <option key={item.id} value={item.id}>{item.name}</option>)}
            </select>
            <div className="flex gap-2 flex-wrap">
              <button onClick={loadSample} disabled={sampleLoading} className="px-3 py-2 text-sm bg-blue-50 text-blue-700 border border-blue-200 hover:bg-blue-100 rounded-lg transition-colors">
                {sampleLoading ? 'Loading...' : 'Load sample config'}
              </button>
              <button onClick={sanitize} className="px-3 py-2 text-sm bg-slate-100 text-slate-700 hover:bg-slate-200 rounded-lg transition-colors">Sanitize</button>
              <button onClick={() => { setConfigText(''); setResult(null); setError(null); }} className="px-3 py-2 text-sm text-slate-600 hover:bg-slate-100 rounded-lg transition-colors">Clear</button>
              <button onClick={validate} disabled={loading || !configText.trim()} className="px-4 py-2 bg-school-600 text-white rounded-lg hover:bg-school-700 disabled:opacity-50 disabled:cursor-not-allowed flex items-center gap-2 text-sm font-semibold transition-colors">
                {loading ? <Loader2 size={16} className="animate-spin" /> : <CheckCircle size={16} />}
                {loading ? 'Analyzing...' : 'Analyze Safely'}
              </button>
            </div>
          </div>
        </div>

        <div className="grid grid-cols-1 lg:grid-cols-2">
          <div className="p-4">
            <textarea
              value={configText}
              onChange={(e) => { setConfigText(e.target.value); setResult(null); }}
              placeholder="Paste a sanitized running configuration, set-style configuration, or exported text here..."
              className="w-full h-[28rem] p-4 font-mono text-sm bg-slate-950 text-emerald-300 rounded-xl resize-none focus:outline-none focus:ring-2 focus:ring-blue-400"
              spellCheck={false}
            />
          </div>
          <div className="p-4 lg:border-l border-slate-100">
            <div {...getRootProps()} className={`h-[28rem] border-2 border-dashed rounded-xl flex flex-col items-center justify-center cursor-pointer transition-colors ${isDragActive ? 'border-school-500 bg-school-50' : 'border-slate-300 hover:border-slate-400'}`}>
              <input {...getInputProps()} />
              <Upload size={48} className="text-slate-400 mb-4" />
              <p className="text-slate-700 font-semibold">Drop sanitized config file here</p>
              <p className="text-slate-400 text-sm mt-1">or click to browse (.txt, .cfg, .config, .conf)</p>
              <p className="text-slate-400 text-xs mt-4">Default API limit: 2 MB</p>
            </div>
          </div>
        </div>
      </div>

      {error && (
        <div className="bg-amber-50 border border-amber-200 rounded-xl p-4 flex items-start gap-3 text-amber-900">
          <AlertCircle size={20} className="flex-none mt-0.5" />
          <p>{error}</p>
        </div>
      )}

      {result && (
        <div className="space-y-6">
          <div className="bg-white rounded-2xl border border-slate-200 p-6 shadow-sm">
            <div className="flex items-start justify-between mb-5 flex-wrap gap-4">
              <div>
                <div className="flex items-center gap-2 flex-wrap">
                  <h2 className="text-xl font-bold text-slate-950">{result.hostname || 'Unknown Device'}</h2>
                  <span className="text-xs font-semibold bg-slate-100 text-slate-700 px-2.5 py-1 rounded-full">{detectedVendor}</span>
                  {parserConfidence !== undefined && <span className="text-xs text-slate-500">Detection confidence {Math.round(Number(parserConfidence) * 100)}%</span>}
                </div>
                <p className="text-sm text-slate-500 mt-1">
                  {result.total_lines} lines · {result.parsed_interfaces?.length || 0} interfaces parsed · {result.parsed_vlans?.length || 0} VLANs parsed
                </p>
                {result.routing?.protocols?.length > 0 && <p className="text-sm text-slate-600 mt-1">Routing detected: {result.routing.protocols.join(', ')}</p>}
                {risk && <p className="text-sm text-slate-800 mt-2"><strong>Risk:</strong> {risk.risk_label} ({risk.risk_score}/100)</p>}
              </div>
              <div className="flex gap-2 flex-wrap">
                <button onClick={downloadMarkdownReport} className="flex items-center gap-2 px-3 py-2 text-sm bg-blue-50 text-blue-700 hover:bg-blue-100 rounded-lg"><FileText size={16}/> Export Markdown</button>
                <button onClick={downloadJsonReport} className="flex items-center gap-2 px-3 py-2 text-sm bg-slate-100 hover:bg-slate-200 rounded-lg"><Download size={16}/> Export JSON</button>
              </div>
            </div>

            {risk?.leadership_summary && <div className="bg-slate-50 border border-slate-200 rounded-xl p-4 mb-5 text-sm text-slate-700">{risk.leadership_summary}</div>}

            <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-5 gap-3">
              <SummaryCard label="Critical" count={result.summary.critical} color="text-red-600" />
              <SummaryCard label="High" count={result.summary.high} color="text-orange-600" />
              <SummaryCard label="Medium" count={result.summary.medium} color="text-amber-600" />
              <SummaryCard label="Low" count={result.summary.low} color="text-blue-600" />
              <SummaryCard label="Total" count={result.summary.total} color="text-slate-950" />
            </div>
          </div>

          <div className="flex gap-2 overflow-x-auto pb-2">
            {['all', 'critical', 'high', 'medium', 'low', 'info'].map(filter => (
              <button key={filter} onClick={() => setActiveFilter(filter)} className={`px-4 py-2 rounded-lg text-sm font-medium capitalize transition-colors whitespace-nowrap ${activeFilter === filter ? 'bg-school-600 text-white' : 'bg-white text-slate-600 hover:bg-slate-100 border border-slate-200'}`}>
                {filter}{filter !== 'all' && result.summary[filter] > 0 && <span className="ml-2 bg-white/20 px-1.5 py-0.5 rounded text-xs">{result.summary[filter]}</span>}
              </button>
            ))}
          </div>

          <div className="space-y-3">
            {filteredFindings.length === 0 ? (
              <div className="bg-emerald-50 border border-emerald-200 rounded-xl p-8 text-center">
                <CheckCircle size={48} className="text-emerald-500 mx-auto mb-3" />
                <p className="text-emerald-900 font-semibold">No {activeFilter !== 'all' ? activeFilter : ''} findings detected by the current rules.</p>
                <p className="text-emerald-700 text-sm mt-1">This is not a guarantee that the configuration is risk-free; unsupported vendor-specific features still require engineering review.</p>
              </div>
            ) : filteredFindings.map((finding, i) => <FindingCard key={`${finding.check_type}-${i}`} finding={finding} index={i} />)}
          </div>
        </div>
      )}
    </div>
  );
}
