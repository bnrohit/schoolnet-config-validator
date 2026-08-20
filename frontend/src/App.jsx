import React, { useState } from 'react';
import { ShieldCheck, FileSearch, TerminalSquare, Wand2, BookOpen, ExternalLink, GitCompareArrows, Network, Radar } from "lucide-react";
import ConfigValidator from './components/ConfigValidator';
import RemediationPanel from './components/RemediationPanel';
import TroubleshootPanel from './components/TroubleshootPanel';
import ChangeImpactLab from './components/ChangeImpactLab';
import NetworkSafetyGraph from './components/NetworkSafetyGraph';
import IncidentInvestigator from './components/IncidentInvestigator';

const tabs = [
  { id: 'validate', label: 'Analyze Config', icon: FileSearch },
  { id: 'impact', label: 'Change Impact Lab', icon: GitCompareArrows },
  { id: 'graph', label: 'Network Safety Graph', icon: Network },
  { id: 'investigate', label: 'Incident Investigator', icon: Radar },
  { id: 'remediate', label: 'Safe Change Plan', icon: Wand2 },
  { id: 'troubleshoot', label: 'Read-Only Live', icon: TerminalSquare },
];

export default function App() {
  const [activeTab, setActiveTab] = useState('investigate');
  const ActiveIcon = tabs.find(t => t.id === activeTab)?.icon || FileSearch;

  return (
    <div className="app-shell">
      <header className="hero">
        <div className="hero-content">
          <div className="brand-row">
            <ShieldCheck className="brand-icon" size={42} />
            <div>
              <h1>SchoolNet Config Validator</h1>
              <p className="tagline">Multi-vendor network intelligence, live incident evidence correlation, peer-aware change safety, and outage prevention.</p>
            </div>
          </div>
          <div className="hero-actions">
            <a href="https://github.com/bnrohit/schoolnet-config-validator" target="_blank" rel="noreferrer" className="btn secondary"><ExternalLink size={18}/> GitHub</a>
            <a href="/docs" target="_blank" rel="noreferrer" className="btn"><BookOpen size={18}/> API Docs</a>
          </div>
        </div>
        <div className="stats-grid">
          <div className="stat"><strong>Incident Investigator</strong><span>DNS · path · services · TLS · evidence</span></div>
          <div className="stat"><strong>Network Safety Graph</strong><span>Peers · paths · gateway context</span></div>
          <div className="stat"><strong>Change pre-flight</strong><span>Blast radius · gate · rollback</span></div>
          <div className="stat"><strong>Safety-first</strong><span>Bounded read-only diagnostics</span></div>
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
            <p>Use only systems and networks you are authorized to administer. Diagnostics are bounded/read-only and results must be validated before production changes.</p>
          </div>
        </section>

        {activeTab === 'validate' && <ConfigValidator />}
        {activeTab === 'impact' && <ChangeImpactLab />}
        {activeTab === 'graph' && <NetworkSafetyGraph />}
        {activeTab === 'investigate' && <IncidentInvestigator />}
        {activeTab === 'remediate' && <RemediationPanel />}
        {activeTab === 'troubleshoot' && <TroubleshootPanel />}
      </main>

      <footer className="footer">
        <ShieldCheck size={16}/> SchoolNet v1.6 — Incident Investigator · Network Safety Graph · change pre-flight · review-first engineering.
      </footer>
    </div>
  );
}
