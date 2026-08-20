import React, { useState } from 'react';
import { ShieldCheck, FileSearch, TerminalSquare, Wand2, BookOpen, ExternalLink, GitCompareArrows, Network } from "lucide-react";
import ConfigValidator from './components/ConfigValidator';
import RemediationPanel from './components/RemediationPanel';
import TroubleshootPanel from './components/TroubleshootPanel';
import ChangeImpactLab from './components/ChangeImpactLab';
import NetworkSafetyGraph from './components/NetworkSafetyGraph';

const tabs = [
  { id: 'validate', label: 'Analyze Config', icon: FileSearch },
  { id: 'impact', label: 'Change Impact Lab', icon: GitCompareArrows },
  { id: 'graph', label: 'Network Safety Graph', icon: Network },
  { id: 'remediate', label: 'Safe Change Plan', icon: Wand2 },
  { id: 'troubleshoot', label: 'Read-Only Live', icon: TerminalSquare },
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
              <p className="tagline">Multi-vendor network intelligence, peer-aware change safety, and outage prevention.</p>
            </div>
          </div>
          <div className="hero-actions">
            <a href="https://github.com/bnrohit/schoolnet-config-validator" target="_blank" rel="noreferrer" className="btn secondary"><ExternalLink size={18}/> GitHub</a>
            <a href="/docs" target="_blank" rel="noreferrer" className="btn"><BookOpen size={18}/> API Docs</a>
          </div>
        </div>
        <div className="stats-grid">
          <div className="stat"><strong>Auto-detect</strong><span>20+ platform families</span></div>
          <div className="stat"><strong>Network Safety Graph</strong><span>Peers · paths · gateway context</span></div>
          <div className="stat"><strong>Change pre-flight</strong><span>Blast radius · gate · rollback</span></div>
          <div className="stat"><strong>Review-first</strong><span>No automatic production changes</span></div>
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
            <p>Use sanitized configuration and read-only evidence. Do not upload passwords, private keys, tokens, or unreviewed production backups.</p>
          </div>
        </section>

        {activeTab === 'validate' && <ConfigValidator />}
        {activeTab === 'impact' && <ChangeImpactLab />}
        {activeTab === 'graph' && <NetworkSafetyGraph />}
        {activeTab === 'remediate' && <RemediationPanel />}
        {activeTab === 'troubleshoot' && <TroubleshootPanel />}
      </main>

      <footer className="footer">
        <ShieldCheck size={16}/> SchoolNet v1.5 — universal analysis · Network Safety Graph · peer-aware change pre-flight · review-first engineering.
      </footer>
    </div>
  );
}
