import React, { useState } from 'react';
import { FileText, Wand2, Download, Copy, CheckCircle, AlertCircle } from 'lucide-react';
import axios from 'axios';

const API_URL = import.meta.env.VITE_API_URL || 'http://localhost:8000';

export default function RemediationPanel() {
  const [configText, setConfigText] = useState('');
  const [vendor, setVendor] = useState('cisco_ios');
  const [script, setScript] = useState('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);
  const [copied, setCopied] = useState(false);
  const [validationResult, setValidationResult] = useState(null);

  const generateRemediation = async () => {
    if (!configText.trim()) {
      setError('Please paste a configuration first');
      return;
    }

    setLoading(true);
    setError(null);

    try {
      // First validate to get findings
      const validateRes = await axios.post(`${API_URL}/api/v1/validate`, {
        config_text: configText,
        vendor
      });

      setValidationResult(validateRes.data);

      if (validateRes.data.summary.total === 0) {
        setScript('! No issues found - no remediation needed!\n! Your configuration looks good.');
        setLoading(false);
        return;
      }

      // Then generate remediation
      const remediateRes = await axios.post(`${API_URL}/api/v1/remediate`, {
        findings: validateRes.data.findings,
        vendor
      });

      setScript(remediateRes.data.script);
    } catch (err) {
      setError(err.response?.data?.detail || 'Failed to generate remediation');
    } finally {
      setLoading(false);
    }
  };

  const copyToClipboard = () => {
    navigator.clipboard.writeText(script);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const downloadScript = () => {
    const blob = new Blob([script], { type: 'text/plain' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = 'remediation-script.txt';
    a.click();
  };

  return (
    <div className="max-w-5xl mx-auto space-y-6">
      <div className="flex items-center gap-3">
        <Wand2 className="text-school-600" size={28} />
        <div>
          <h1 className="text-2xl font-bold text-gray-900">Auto Remediation</h1>
          <p className="text-gray-500">Generate fix scripts from detected configuration issues</p>
        </div>
      </div>

      {/* Input */}
      <div className="bg-white rounded-xl border border-gray-200 overflow-hidden">
        <div className="p-4 border-b border-gray-100 flex items-center justify-between">
          <select 
            value={vendor} 
            onChange={(e) => setVendor(e.target.value)}
            className="bg-gray-50 border border-gray-300 rounded-lg px-3 py-2 text-sm"
          >
            <option value="cisco_ios">Cisco IOS</option>
            <option value="cisco_iosxe">Cisco IOS-XE</option>
            <option value="aruba_aoscx">Aruba AOS-CX</option>
          </select>

          <button
            onClick={generateRemediation}
            disabled={loading}
            className="px-4 py-2 bg-school-600 text-white rounded-lg hover:bg-school-700 disabled:opacity-50 flex items-center gap-2 text-sm font-medium"
          >
            {loading ? 'Analyzing...' : 'Generate Fix Script'}
          </button>
        </div>

        <textarea
          value={configText}
          onChange={(e) => setConfigText(e.target.value)}
          placeholder={`! Paste configuration to analyze...
! The tool will detect issues and generate a fix script`}
          className="w-full h-64 p-4 font-mono text-sm bg-gray-900 text-green-400 resize-none focus:outline-none"
          spellCheck={false}
        />
      </div>

      {error && (
        <div className="bg-red-50 border border-red-200 rounded-lg p-4 flex items-center gap-3 text-red-700">
          <AlertCircle size={20} />
          <p>{error}</p>
        </div>
      )}

      {/* Validation Summary */}
      {validationResult && validationResult.summary.total > 0 && (
        <div className="bg-white rounded-xl border border-gray-200 p-6">
          <h3 className="font-semibold text-gray-900 mb-3">Issues Found</h3>
          <div className="grid grid-cols-5 gap-3">
            {Object.entries(validationResult.summary).filter(([k]) => k !== 'total').map(([key, count]) => (
              <div key={key} className="text-center p-3 bg-gray-50 rounded-lg">
                <p className={`text-xl font-bold ${
                  key === 'critical' ? 'text-red-600' :
                  key === 'high' ? 'text-orange-600' :
                  key === 'medium' ? 'text-yellow-600' :
                  key === 'low' ? 'text-blue-600' : 'text-gray-600'
                }`}>{count}</p>
                <p className="text-xs text-gray-500 capitalize">{key}</p>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Generated Script */}
      {script && (
        <div className="bg-white rounded-xl border border-gray-200 overflow-hidden">
          <div className="p-4 border-b border-gray-100 flex items-center justify-between">
            <div className="flex items-center gap-2">
              <FileText size={20} className="text-school-600" />
              <h3 className="font-semibold text-gray-900">Generated Remediation Script</h3>
            </div>
            <div className="flex gap-2">
              <button
                onClick={copyToClipboard}
                className="flex items-center gap-2 px-3 py-2 text-sm bg-gray-100 hover:bg-gray-200 rounded-lg transition-colors"
              >
                {copied ? <CheckCircle size={16} className="text-green-500" /> : <Copy size={16} />}
                {copied ? 'Copied!' : 'Copy'}
              </button>
              <button
                onClick={downloadScript}
                className="flex items-center gap-2 px-3 py-2 text-sm bg-school-600 text-white hover:bg-school-700 rounded-lg transition-colors"
              >
                <Download size={16} />
                Download
              </button>
            </div>
          </div>

          <div className="relative">
            <pre className="p-4 font-mono text-sm bg-gray-900 text-green-400 overflow-x-auto max-h-96 overflow-y-auto">
              {script}
            </pre>
          </div>

          <div className="p-4 bg-yellow-50 border-t border-yellow-200">
            <div className="flex items-start gap-3">
              <AlertCircle size={18} className="text-yellow-600 mt-0.5 flex-shrink-0" />
              <div>
                <p className="text-sm font-medium text-yellow-800">⚠️ Review Before Applying</p>
                <p className="text-sm text-yellow-700 mt-1">
                  This script was auto-generated. Always review in a lab environment first. 
                  Apply during a maintenance window. Save your current config with <code className="bg-yellow-100 px-1 rounded">write memory</code> before changes.
                </p>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
