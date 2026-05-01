import React, { useState, useCallback } from 'react';
import { useDropzone } from 'react-dropzone';
import {
  Upload, AlertCircle, CheckCircle, AlertTriangle,
  Info, ChevronDown, ChevronUp, Download, Shield, Loader2, FileText, Sparkles
} from 'lucide-react';
import axios from 'axios';

const API_URL = import.meta.env.VITE_API_URL || 'http://localhost:8000';

const severityConfig = {
  critical: { icon: AlertCircle, color: 'text-red-600', bg: 'bg-red-50', border: 'border-red-400', label: 'Critical' },
  high: { icon: AlertTriangle, color: 'text-orange-600', bg: 'bg-orange-50', border: 'border-orange-400', label: 'High' },
  medium: { icon: AlertTriangle, color: 'text-yellow-600', bg: 'bg-yellow-50', border: 'border-yellow-400', label: 'Medium' },
  low: { icon: Info, color: 'text-blue-600', bg: 'bg-blue-50', border: 'border-blue-400', label: 'Low' },
  info: { icon: Info, color: 'text-gray-600', bg: 'bg-gray-50', border: 'border-gray-400', label: 'Info' },
};

function FindingCard({ finding, index }) {
  const [expanded, setExpanded] = useState(false);
  const config = severityConfig[finding.severity] || severityConfig.info;
  const Icon = config.icon;

  return (
    <div className={`rounded-lg border-l-4 ${config.border} ${config.bg} overflow-hidden`}>
      <button onClick={() => setExpanded(!expanded)} className="w-full p-4 flex items-start gap-3 text-left hover:bg-white/50 transition-colors">
        <Icon size={20} className={`${config.color} mt-0.5 flex-shrink-0`} />
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2 flex-wrap">
            <span className={`text-xs font-bold px-2 py-0.5 rounded ${config.color} bg-white/60`}>{config.label}</span>
            <span className="text-xs text-gray-500">#{index + 1}</span>
            {finding.interface && <span className="text-xs font-mono bg-gray-800 text-white px-2 py-0.5 rounded">{finding.interface}</span>}
          </div>
          <p className="mt-1 font-medium text-gray-900">{finding.message}</p>
        </div>
        {expanded ? <ChevronUp size={18} className="text-gray-400" /> : <ChevronDown size={18} className="text-gray-400" />}
      </button>
      {expanded && (
        <div className="px-4 pb-4 pt-0">
          <div className="bg-white rounded-lg p-4 space-y-3">
            <div>
              <p className="text-xs font-semibold text-gray-500 uppercase tracking-wider">Recommended Action</p>
              <p className="text-sm text-gray-700 mt-1">{finding.remediation}</p>
            </div>
            {finding.raw_config && (
              <div>
                <p className="text-xs font-semibold text-gray-500 uppercase tracking-wider">Sanitized Config Snippet</p>
                <pre className="mt-1 text-xs bg-gray-900 text-green-400 p-3 rounded-lg overflow-x-auto">{finding.raw_config}</pre>
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  );
}

function SummaryCard({ label, count, color }) {
  return (
    <div className="bg-white rounded-lg border border-gray-200 p-4 text-center">
      <p className={`text-2xl font-bold ${color}`}>{count}</p>
      <p className="text-xs text-gray-500 mt-1">{label}</p>
    </div>
  );
}

export default function ConfigValidator() {
  const [configText, setConfigText] = useState('');
  const [vendor, setVendor] = useState('cisco_ios');
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
    };
    reader.readAsText(file);
  }, []);

  const { getRootProps, getInputProps, isDragActive } = useDropzone({
    onDrop,
    accept: { 'text/plain': ['.txt', '.cfg', '.config'] },
    multiple: false,
  });

  const loadDemo = async () => {
    setSampleLoading(true);
    setError(null);
    try {
      const response = await axios.get(`${API_URL}/api/v1/examples`);
      setConfigText(response.data.broken_config || '');
      setResult(null);
      setVendor('cisco_ios');
    } catch (err) {
      setError('Could not load demo config. Is the backend running?');
    } finally {
      setSampleLoading(false);
    }
  };

  const sanitize = async () => {
    if (!configText.trim()) {
      setError('Paste a configuration before sanitizing');
      return;
    }
    try {
      const response = await axios.post(`${API_URL}/api/v1/sanitize`, { config_text: configText, vendor });
      setConfigText(response.data.sanitized_config_text);
      setError(response.data.changed ? null : 'No obvious secrets found to redact.');
    } catch (err) {
      setError(err.response?.data?.detail || 'Sanitize failed');
    }
  };

  const validate = async () => {
    if (!configText.trim()) {
      setError('Please paste or upload a configuration');
      return;
    }
    setLoading(true);
    setError(null);
    try {
      const response = await axios.post(`${API_URL}/api/v1/validate`, { config_text: configText, vendor });
      setResult(response.data);
      setActiveFilter('all');
    } catch (err) {
      setError(err.response?.data?.detail || 'Validation failed. Is the backend running?');
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
    a.download = `${result.hostname || 'switch'}_schoolnet_report.json`;
    a.click();
  };

  const downloadMarkdownReport = async () => {
    if (!result) return;
    try {
      const response = await axios.post(`${API_URL}/api/v1/report/markdown`, { result }, { responseType: 'text' });
      const blob = new Blob([response.data], { type: 'text/markdown' });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `${result.hostname || 'switch'}_schoolnet_report.md`;
      a.click();
    } catch (err) {
      setError('Markdown report generation failed');
    }
  };

  const filteredFindings = result?.findings?.filter(f => activeFilter === 'all' || f.severity === activeFilter) || [];
  const risk = result?.executive_summary;

  return (
    <div className="max-w-5xl mx-auto space-y-6">
      <div className="flex items-center gap-3">
        <Shield className="text-school-600" size={28} />
        <div>
          <h1 className="text-2xl font-bold text-gray-900">Validate Configuration</h1>
          <p className="text-gray-500">Paste, sanitize, validate, and export a leadership-ready report.</p>
        </div>
      </div>

      <div className="bg-blue-50 border border-blue-200 rounded-lg p-4 flex items-start gap-3">
        <Sparkles size={20} className="text-blue-600" />
        <div>
          <p className="font-bold text-blue-900">New user path</p>
          <p className="text-sm text-blue-800">Click “Load demo config”, validate it, then try your own sanitized config. No network access is required for offline validation.</p>
        </div>
      </div>

      <div className="bg-white rounded-xl border border-gray-200 overflow-hidden">
        <div className="p-4 border-b border-gray-100 flex items-center justify-between flex-wrap gap-3">
          <select value={vendor} onChange={(e) => setVendor(e.target.value)} className="bg-gray-50 border border-gray-300 rounded-lg px-3 py-2 text-sm">
            <option value="cisco_ios">Cisco IOS</option>
            <option value="cisco_iosxe">Cisco IOS-XE</option>
            <option value="aruba_aoscx">Aruba AOS-CX</option>
            <option value="aruba_aos">Aruba AOS-Switch</option>
          </select>
          <div className="flex gap-2 flex-wrap">
            <button onClick={loadDemo} disabled={sampleLoading} className="px-3 py-2 text-sm bg-blue-50 text-blue-700 hover:bg-blue-100 rounded-lg transition-colors">
              {sampleLoading ? 'Loading...' : 'Load demo config'}
            </button>
            <button onClick={sanitize} className="px-3 py-2 text-sm bg-gray-100 text-gray-700 hover:bg-gray-200 rounded-lg transition-colors">Sanitize</button>
            <button onClick={() => { setConfigText(''); setResult(null); }} className="px-3 py-2 text-sm text-gray-600 hover:bg-gray-100 rounded-lg transition-colors">Clear</button>
            <button onClick={validate} disabled={loading || !configText.trim()} className="px-4 py-2 bg-school-600 text-white rounded-lg hover:bg-school-700 disabled:opacity-50 disabled:cursor-not-allowed flex items-center gap-2 text-sm font-medium transition-colors">
              {loading ? <Loader2 size={16} className="animate-spin" /> : <CheckCircle size={16} />}
              {loading ? 'Validating...' : 'Validate'}
            </button>
          </div>
        </div>

        <div className="grid grid-cols-1 lg:grid-cols-2">
          <div className="p-4">
            <textarea
              value={configText}
              onChange={(e) => { setConfigText(e.target.value); setResult(null); }}
              placeholder="Paste sanitized running-config here, or click Load demo config."
              className="w-full h-96 p-4 font-mono text-sm bg-gray-900 text-green-400 rounded-lg resize-none focus:outline-none"
              spellCheck={false}
            />
          </div>
          <div className="p-4 border-l border-gray-100">
            <div {...getRootProps()} className={`h-96 border-2 border-dashed rounded-lg flex flex-col items-center justify-center cursor-pointer transition-colors ${isDragActive ? 'border-school-500 bg-school-50' : 'border-gray-300 hover:border-gray-400'}`}>
              <input {...getInputProps()} />
              <Upload size={48} className="text-gray-400 mb-4" />
              <p className="text-gray-600 font-medium">Drop config file here</p>
              <p className="text-gray-400 text-sm mt-1">or click to browse (.txt, .cfg, .config)</p>
              <p className="text-gray-400 text-xs mt-4">Default API limit: 2 MB</p>
            </div>
          </div>
        </div>
      </div>

      {error && (
        <div className="bg-yellow-50 border border-yellow-200 rounded-lg p-4 flex items-center gap-3 text-yellow-800">
          <AlertCircle size={20} />
          <p>{error}</p>
        </div>
      )}

      {result && (
        <div className="space-y-6">
          <div className="bg-white rounded-xl border border-gray-200 p-6">
            <div className="flex items-center justify-between mb-4 flex-wrap gap-3">
              <div>
                <h2 className="text-lg font-bold text-gray-900">{result.hostname || 'Unknown Device'}</h2>
                <p className="text-sm text-gray-500">{result.vendor} • {result.total_lines} lines • {result.parsed_interfaces.length} interfaces • {result.parsed_vlans.length} VLANs</p>
                {risk && <p className="text-sm text-gray-700 mt-1"><strong>Risk:</strong> {risk.risk_label} ({risk.risk_score}/100)</p>}
              </div>
              <div className="flex gap-2 flex-wrap">
                <button onClick={downloadMarkdownReport} className="flex items-center gap-2 px-3 py-2 text-sm bg-blue-50 text-blue-700 hover:bg-blue-100 rounded-lg transition-colors"><FileText size={16}/> Export Markdown</button>
                <button onClick={downloadJsonReport} className="flex items-center gap-2 px-3 py-2 text-sm bg-gray-100 hover:bg-gray-200 rounded-lg transition-colors"><Download size={16}/> Export JSON</button>
              </div>
            </div>
            {risk?.leadership_summary && <div className="bg-gray-50 border border-gray-200 rounded-lg p-4 mb-4 text-sm text-gray-700">{risk.leadership_summary}</div>}
            <div className="grid grid-cols-5 gap-3">
              <SummaryCard label="Critical" count={result.summary.critical} color="text-red-600" />
              <SummaryCard label="High" count={result.summary.high} color="text-orange-600" />
              <SummaryCard label="Medium" count={result.summary.medium} color="text-yellow-600" />
              <SummaryCard label="Low" count={result.summary.low} color="text-blue-600" />
              <SummaryCard label="Total" count={result.summary.total} color="text-gray-900" />
            </div>
          </div>

          <div className="flex gap-2 overflow-x-auto pb-2">
            {['all', 'critical', 'high', 'medium', 'low', 'info'].map(filter => (
              <button key={filter} onClick={() => setActiveFilter(filter)} className={`px-4 py-2 rounded-lg text-sm font-medium capitalize transition-colors ${activeFilter === filter ? 'bg-school-600 text-white' : 'bg-white text-gray-600 hover:bg-gray-100 border border-gray-200'}`}>
                {filter}{filter !== 'all' && result.summary[filter] > 0 && <span className="ml-2 bg-white/20 px-1.5 py-0.5 rounded text-xs">{result.summary[filter]}</span>}
              </button>
            ))}
          </div>

          <div className="space-y-3">
            {filteredFindings.length === 0 ? (
              <div className="bg-green-50 border border-green-200 rounded-lg p-8 text-center">
                <CheckCircle size={48} className="text-green-500 mx-auto mb-3" />
                <p className="text-green-800 font-medium">No {activeFilter !== 'all' ? activeFilter : ''} issues found.</p>
                <p className="text-green-600 text-sm mt-1">Configuration looks good for this filter.</p>
              </div>
            ) : filteredFindings.map((finding, i) => <FindingCard key={i} finding={finding} index={i} />)}
          </div>
        </div>
      )}
    </div>
  );
}
