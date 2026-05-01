import React, { useState } from 'react';
import { ShieldCheck, FileSearch, TerminalSquare, Wand2, Github, BookOpen, UploadCloud } from 'lucide-react';
import ConfigValidator from './components/ConfigValidator';
import RemediationPanel from './components/RemediationPanel';
import TroubleshootPanel from './components/TroubleshootPanel';

const tabs = [
  { id: 'validate', label: 'Validate Config', icon: FileSearch },
  { id: 'remediate', label: 'Fix Script', icon: Wand2 },
  { id: 'troubleshoot', label: 'Live Checks', icon: TerminalSquare },
];

export default function App() {
  const [activeTab, setActiveTab] = useState('validate');
  const ActiveIcon = tabs.find(t => t.id === activeTab)?.icon || FileSearch;

  return (
    <div className="app-shell">
      <header className="hero">
        <div className="hero-content">
          <div className="brand-row">
            <ShieldCheck className="brand-icon" size={42} />
            <div>
              <h1>SchoolNet Config Validator</h1>
              <p className="tagline">Open-source K-12 network configuration validation and outage prevention toolkit.</p>
            </div>
          </div>
          <div className="hero-actions">
            <a href="https://github.com/bnrohit/schoolnet-config-validator" target="_blank" rel="noreferrer" className="btn secondary"><Github size={18}/> GitHub</a>
            <a href="/docs" target="_blank" rel="noreferrer" className="btn"><BookOpen size={18}/> API Docs</a>
          </div>
        </div>
        <div className="stats-grid">
          <div className="stat"><strong>7+</strong><span>Validation checks</span></div>
          <div className="stat"><strong>Multi-vendor</strong><span>Cisco + Aruba ready</span></div>
          <div className="stat"><strong>Safe-first</strong><span>Offline config review</span></div>
          <div className="stat"><strong>K-12</strong><span>Built for school IT</span></div>
        </div>
      </header>

      <main className="main-card">
        <nav className="tabs" aria-label="Application tabs">
          {tabs.map(tab => {
            const Icon = tab.icon;
            return (
              <button key={tab.id} className={activeTab === tab.id ? 'tab active' : 'tab'} onClick={() => setActiveTab(tab.id)}>
                <Icon size={18}/>{tab.label}
              </button>
            );
          })}
        </nav>

        <section className="panel-heading">
          <ActiveIcon size={24}/>
          <div>
            <h2>{tabs.find(t => t.id === activeTab)?.label}</h2>
            <p>Use sanitized configs only. Do not upload passwords, private keys, or full production backups.</p>
          </div>
        </section>

        {activeTab === 'validate' && <ConfigValidator />}
        {activeTab === 'remediate' && <RemediationPanel />}
        {activeTab === 'troubleshoot' && <TroubleshootPanel />}
      </main>

      <footer className="footer">
        <UploadCloud size={16}/> MVP v1.1 — designed for visibility, documentation, and community contributions.
      </footer>
    </div>
  );
}
