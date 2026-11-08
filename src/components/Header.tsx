import React from 'react';
import { Shield, Play } from 'lucide-react';

interface HeaderProps {
  activeTab: string;
  setActiveTab: (tab: string) => void;
  onRunQuickTests: () => void;
  isTesting: boolean;
}

const NAV_ITEMS = [
  { id: 'simulator', label: 'Agent Simulator' },
  { id: 'policies', label: 'RBAC & Config' },
  { id: 'siem', label: 'SIEM Audit' },
  { id: 'commands', label: 'Command Catalog' },
  { id: 'tests', label: 'Verification Suite' },
  { id: 'deployment', label: 'Docker & Linux' },
];

/**
 * 3-Zone Top Bar Navigation Header:
 * Zone 1: Wordmark / Identity
 * Zone 2: Clean single-line text navigation links
 * Zone 3: Primary security test trigger
 */
export const Header: React.FC<HeaderProps> = ({
  activeTab,
  setActiveTab,
  onRunQuickTests,
  isTesting,
}) => {
  return (
    <header className="border-b border-slate-800 bg-slate-950 text-slate-100">
      <div className="max-w-7xl mx-auto flex items-center justify-between gap-6 px-6 py-3.5">
        {/* Zone 1: Brand Wordmark */}
        <div className="flex items-center gap-2.5 whitespace-nowrap shrink-0">
          <Shield className="w-5 h-5 text-emerald-400 shrink-0" />
          <span className="text-base font-bold tracking-tight text-white">
            Active Directory LDAPS Proxy
          </span>
        </div>

        {/* Zone 2: Primary Desktop Navigation */}
        <nav className="hidden lg:flex items-center gap-6 text-sm font-medium">
          {NAV_ITEMS.map((item) => (
            <button
              key={item.id}
              onClick={() => setActiveTab(item.id)}
              className={`whitespace-nowrap shrink-0 transition-colors py-1 cursor-pointer ${
                activeTab === item.id
                  ? 'text-white border-b-2 border-emerald-400 font-semibold'
                  : 'text-slate-400 hover:text-slate-200'
              }`}
            >
              {item.label}
            </button>
          ))}
        </nav>

        {/* Zone 3: Single Primary Action */}
        <div className="flex items-center gap-3 shrink-0">
          <button
            onClick={onRunQuickTests}
            disabled={isTesting}
            className="flex items-center gap-2 px-3.5 py-1.5 text-xs font-semibold text-slate-950 bg-emerald-400 rounded-md hover:bg-emerald-300 transition-colors disabled:opacity-50 whitespace-nowrap shrink-0 cursor-pointer"
          >
            <Play className="w-3.5 h-3.5 fill-current" />
            <span>{isTesting ? 'Validating...' : 'Run Security Tests'}</span>
          </button>
        </div>
      </div>

      {/* Responsive Mobile / Tablet Navigation Bar */}
      <nav className="flex lg:hidden items-center gap-4 px-6 py-2 border-t border-slate-900 overflow-x-auto text-xs font-medium">
        {NAV_ITEMS.map((item) => (
          <button
            key={item.id}
            onClick={() => setActiveTab(item.id)}
            className={`whitespace-nowrap shrink-0 py-1 transition-colors ${
              activeTab === item.id
                ? 'text-emerald-400 font-semibold border-b border-emerald-400'
                : 'text-slate-400 hover:text-slate-200'
            }`}
          >
            {item.label}
          </button>
        ))}
      </nav>
    </header>
  );
};
