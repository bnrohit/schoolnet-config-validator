import React, { useState } from 'react';
import { Terminal, Play, Loader2, AlertCircle, CheckCircle, Server, Lock } from 'lucide-react';
import axios from 'axios';

const API_URL = import.meta.env.VITE_API_URL || 'http://localhost:8000';

const commandCategories = {
  basic: { label: 'Basic Info', desc: 'Version, uptime, users' },
  interfaces: { label: 'Interfaces', desc: 'Status, errors, descriptions' },
  vlan: { label: 'VLAN', desc: 'VLAN config and trunks' },
  stp: { label: 'STP', desc: 'Spanning tree topology' },
  mac: { label: 'MAC Table', desc: 'MAC address learning' },
  arp: { label: 'ARP/Routing', desc: 'ARP table and routes' },
  errors: { label: 'Errors', desc: 'Interface errors and logs' },
  neighbors: { label: 'Neighbors', desc: 'CDP/LLDP devices' },
  poe: { label: 'PoE', desc: 'Power over Ethernet' },
  security: { label: 'Security', desc: 'Port security status' },
  all: { label: 'All Checks', desc: 'Complete diagnostic suite' },
};

function CommandOutput({ result }) {
  if (!result) return null;

  return (
    <div className="bg-gray-900 rounded-lg overflow-hidden">
      <div className="bg-gray-800 px-4 py-2 flex items-center justify-between">
        <span className="text-xs font-mono text-gray-400">{result.category}</span>
        <span className="text-xs text-gray-500">{result.description}</span>
      </div>
      <div className="p-4 space-y-4 max-h-96 overflow-y-auto">
        {result.results?.map((cmd, i) => (
          <div key={i} className="space-y-2">
            <div className="flex items-center gap-2">
              <span className="text-green-400 font-mono text-sm">$</span>
              <span className="text-green-300 font-mono text-sm">{cmd.command}</span>
            </div>
            <pre className="text-gray-300 text-xs font-mono whitespace-pre-wrap bg-gray-800/50 p-3 rounded overflow-x-auto">
              {typeof cmd.raw === 'string' ? cmd.raw : JSON.stringify(cmd.raw, null, 2)}
            </pre>
          </div>
        ))}
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
      setError('Please fill in all connection fields');
      return;
    }

    setLoading(true);
    setError(null);
    setResults(null);

    try {
      const response = await axios.post(`${API_URL}/api/v1/troubleshoot`, {
        host,
        username,
        password,
        device_type: deviceType,
        check: selectedCheck
      });
      setResults(response.data);
    } catch (err) {
      setError(err.response?.data?.detail || 'Connection failed. Check IP, credentials, and SSH access.');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="max-w-5xl mx-auto space-y-6">
      <div className="flex items-center gap-3">
        <Terminal className="text-school-600" size={28} />
        <div>
          <h1 className="text-2xl font-bold text-gray-900">Live Troubleshoot</h1>
          <p className="text-gray-500">SSH into switches and run diagnostic commands</p>
        </div>
      </div>

      {/* Connection Card */}
      <div className="bg-white rounded-xl border border-gray-200 p-6">
        <h2 className="text-lg font-semibold text-gray-900 mb-4 flex items-center gap-2">
          <Server size={20} />
          Connection
        </h2>

        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
          <div>
            <label className="block text-sm font-medium text-gray-700 mb-1">Host/IP</label>
            <input
              type="text"
              value={host}
              onChange={(e) => setHost(e.target.value)}
              placeholder="192.168.1.10"
              className="w-full px-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-school-500 focus:border-school-500"
            />
          </div>

          <div>
            <label className="block text-sm font-medium text-gray-700 mb-1">Username</label>
            <input
              type="text"
              value={username}
              onChange={(e) => setUsername(e.target.value)}
              placeholder="admin"
              className="w-full px-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-school-500 focus:border-school-500"
            />
          </div>

          <div>
            <label className="block text-sm font-medium text-gray-700 mb-1">Password</label>
            <div className="relative">
              <input
                type={showPassword ? 'text' : 'password'}
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                placeholder="••••••••"
                className="w-full px-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-school-500 focus:border-school-500 pr-10"
              />
              <button
                onClick={() => setShowPassword(!showPassword)}
                className="absolute right-3 top-1/2 -translate-y-1/2 text-gray-400 hover:text-gray-600"
              >
                <Lock size={16} />
              </button>
            </div>
          </div>

          <div>
            <label className="block text-sm font-medium text-gray-700 mb-1">Device Type</label>
            <select
              value={deviceType}
              onChange={(e) => setDeviceType(e.target.value)}
              className="w-full px-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-school-500 focus:border-school-500"
            >
              <option value="cisco_ios">Cisco IOS</option>
              <option value="cisco_iosxe">Cisco IOS-XE</option>
              <option value="aruba_aoscx">Aruba AOS-CX</option>
            </select>
          </div>
        </div>
      </div>

      {/* Check Selection */}
      <div className="bg-white rounded-xl border border-gray-200 p-6">
        <h2 className="text-lg font-semibold text-gray-900 mb-4">Select Diagnostic</h2>

        <div className="grid grid-cols-2 sm:grid-cols-3 md:grid-cols-4 lg:grid-cols-6 gap-3">
          {Object.entries(commandCategories).map(([key, { label, desc }]) => (
            <button
              key={key}
              onClick={() => setSelectedCheck(key)}
              className={`p-3 rounded-lg border text-left transition-all ${
                selectedCheck === key
                  ? 'border-school-500 bg-school-50 ring-2 ring-school-200'
                  : 'border-gray-200 hover:border-gray-300 hover:bg-gray-50'
              }`}
            >
              <p className={`font-medium text-sm ${selectedCheck === key ? 'text-school-700' : 'text-gray-700'}`}>
                {label}
              </p>
              <p className="text-xs text-gray-500 mt-1">{desc}</p>
            </button>
          ))}
        </div>

        <button
          onClick={runTroubleshoot}
          disabled={loading}
          className="mt-6 w-full md:w-auto px-6 py-3 bg-school-600 text-white rounded-lg hover:bg-school-700 disabled:opacity-50 flex items-center justify-center gap-2 font-medium transition-colors"
        >
          {loading ? <Loader2 size={18} className="animate-spin" /> : <Play size={18} />}
          {loading ? 'Running diagnostics...' : 'Run Diagnostics'}
        </button>
      </div>

      {error && (
        <div className="bg-red-50 border border-red-200 rounded-lg p-4 flex items-center gap-3 text-red-700">
          <AlertCircle size={20} />
          <div>
            <p className="font-medium">Connection Error</p>
            <p className="text-sm">{error}</p>
          </div>
        </div>
      )}

      {/* Results */}
      {results && (
        <div className="space-y-4">
          <div className="flex items-center justify-between">
            <h2 className="text-lg font-semibold text-gray-900 flex items-center gap-2">
              <CheckCircle size={20} className="text-green-500" />
              Results from {results.host}
            </h2>
            <span className="text-sm text-gray-500">{results.device_type}</span>
          </div>

          {Array.isArray(results.results) ? (
            results.results.map((category, i) => (
              <CommandOutput key={i} result={category} />
            ))
          ) : (
            <CommandOutput result={results.results} />
          )}
        </div>
      )}
    </div>
  );
}
