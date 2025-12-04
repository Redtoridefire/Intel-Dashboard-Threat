import React, { useState, useEffect, useCallback } from 'react';
import { PieChart, Pie, Cell, Tooltip, ResponsiveContainer } from 'recharts';
import { mapThreatToMitre, generateMitigations, generateRemediation, getMitreTechniqueUrl, MITRE_TACTICS } from './mitreAttack';
import { mapThreatToCVEs, generateVulnerabilityBreakdown, generateCVEMitigation, formatCVSS, getCVELinks, getCVEPriority, mapCVEToMitre } from './cveUtils';

// API Configuration
const API_BASE = '/api';
const API_KEY = process.env.REACT_APP_DASHBOARD_API_KEY || '';

const api = {
  async get(endpoint) {
    const headers = {};
    if (API_KEY) headers['X-API-Key'] = API_KEY;
    const response = await fetch(`${API_BASE}?endpoint=${endpoint}`, { headers });
    if (!response.ok) {
      const error = await response.json().catch(() => ({ error: 'Request failed' }));
      throw new Error(error.error || 'API request failed');
    }
    return response.json();
  },
  async post(endpoint, data) {
    const headers = { 'Content-Type': 'application/json' };
    if (API_KEY) headers['X-API-Key'] = API_KEY;
    const response = await fetch(`${API_BASE}?endpoint=${endpoint}`, { method: 'POST', headers, body: JSON.stringify(data) });
    if (!response.ok) {
      const error = await response.json().catch(() => ({ error: 'Request failed' }));
      throw new Error(error.error || 'API request failed');
    }
    return response.json();
  }
};

const SeverityBadge = ({ severity }) => {
  const colors = {
    critical: 'bg-red-500/20 text-red-400 border-red-500/50',
    high: 'bg-orange-500/20 text-orange-400 border-orange-500/50',
    medium: 'bg-yellow-500/20 text-yellow-400 border-yellow-500/50',
    low: 'bg-blue-500/20 text-blue-400 border-blue-500/50',
  };
  return <span className={`px-2 py-0.5 text-xs font-mono uppercase border rounded ${colors[severity] || colors.medium}`}>{severity}</span>;
};

const StatusIndicator = ({ status }) => {
  const styles = {
    connected: 'bg-emerald-500 shadow-emerald-500/50',
    api_key_required: 'bg-gray-500 shadow-gray-500/50',
  };
  return <div className={`w-2 h-2 rounded-full shadow-lg ${styles[status] || styles.api_key_required} animate-pulse`} />;
};

const GlowCard = ({ children, className = '' }) => (
  <div className={`bg-slate-900/80 border border-slate-700/50 rounded-lg backdrop-blur-sm transition-all duration-300 hover:border-slate-600 hover:shadow-xl hover:shadow-cyan-500/10 ${className}`}>
    {children}
  </div>
);

const MetricCard = ({ label, value, icon, loading }) => (
  <GlowCard className="p-4">
    <div className="flex items-start justify-between">
      <div>
        <p className="text-slate-500 text-xs font-mono uppercase tracking-wider">{label}</p>
        {loading ? <div className="h-8 w-20 bg-slate-700 animate-pulse rounded mt-1" /> : <p className="text-2xl font-bold text-white mt-1 font-mono">{value}</p>}
      </div>
      <div className="text-3xl opacity-50">{icon}</div>
    </div>
  </GlowCard>
);

const LoadingSkeleton = ({ rows = 5 }) => (
  <div className="space-y-3">
    {[...Array(rows)].map((_, i) => (
      <div key={i} className="flex items-center gap-4 p-3 bg-slate-800/50 rounded-lg animate-pulse">
        <div className="w-10 h-10 bg-slate-700 rounded-lg" />
        <div className="flex-1 space-y-2"><div className="h-4 w-48 bg-slate-700 rounded" /><div className="h-3 w-32 bg-slate-700 rounded" /></div>
        <div className="h-6 w-16 bg-slate-700 rounded" />
      </div>
    ))}
  </div>
);

const ErrorMessage = ({ message, onRetry }) => (
  <div className="p-6 text-center">
    <div className="text-4xl mb-3">⚠️</div>
    <p className="text-red-400 mb-4">{message}</p>
    {onRetry && <button onClick={onRetry} className="px-4 py-2 bg-slate-700 text-white rounded-lg hover:bg-slate-600">Retry</button>}
  </div>
);

export default function ThreatIntelDashboard() {
  const [activeTab, setActiveTab] = useState('overview');
  const [threats, setThreats] = useState([]);
  const [feeds, setFeeds] = useState([]);
  const [cves, setCves] = useState([]);
  const [news, setNews] = useState([]);
  const [selectedThreat, setSelectedThreat] = useState(null);
  const [selectedCVE, setSelectedCVE] = useState(null);
  const [threatDetailTab, setThreatDetailTab] = useState('overview');
  const [cveDetailTab, setCveDetailTab] = useState('overview');
  const [searchQuery, setSearchQuery] = useState('');
  const [cveSearchQuery, setCveSearchQuery] = useState('');
  const [newsSearchQuery, setNewsSearchQuery] = useState('');
  const [newsCategoryFilter, setNewsCategoryFilter] = useState('all');
  const [filterSeverity, setFilterSeverity] = useState('all');
  const [filterSource, setFilterSource] = useState('all');
  const [filterDateRange, setFilterDateRange] = useState('all');
  const [filterCVECriticality, setFilterCVECriticality] = useState('all');
  const [filterRansomware, setFilterRansomware] = useState(false);
  const [threatFeedErrors, setThreatFeedErrors] = useState([]);
  const [currentTime, setCurrentTime] = useState(new Date());
  const [loading, setLoading] = useState({ threats: true, feeds: true, cves: true, news: true });
  const [errors, setErrors] = useState({});
  const [unifiedSearchQuery, setUnifiedSearchQuery] = useState('');
  const [unifiedSearchResults, setUnifiedSearchResults] = useState(null);
  const [searchLoading, setSearchLoading] = useState(false);
  const [showAdvancedFilters, setShowAdvancedFilters] = useState(false);

  useEffect(() => {
    const timer = setInterval(() => setCurrentTime(new Date()), 1000);
    return () => clearInterval(timer);
  }, []);

  const fetchFeeds = useCallback(async () => {
    try {
      setLoading(prev => ({ ...prev, feeds: true }));
      const data = await api.get('feeds');
      setFeeds(data.feeds);
      setErrors(prev => ({ ...prev, feeds: null }));
    } catch (error) {
      setErrors(prev => ({ ...prev, feeds: error.message }));
    } finally {
      setLoading(prev => ({ ...prev, feeds: false }));
    }
  }, []);

  const fetchThreats = useCallback(async () => {
    try {
      setLoading(prev => ({ ...prev, threats: true }));
      const data = await api.get('threats');
      setThreats(data.threats || []);
      setThreatFeedErrors(data.errors || []);
      setErrors(prev => ({ ...prev, threats: null }));
    } catch (error) {
      setErrors(prev => ({ ...prev, threats: error.message }));
      setThreatFeedErrors([]);
    } finally {
      setLoading(prev => ({ ...prev, threats: false }));
    }
  }, []);

  const fetchCVEs = useCallback(async () => {
    try {
      setLoading(prev => ({ ...prev, cves: true }));
      const data = await api.get('cves');
      setCves(data.cves || []);
      setErrors(prev => ({ ...prev, cves: null }));
    } catch (error) {
      setErrors(prev => ({ ...prev, cves: error.message }));
    } finally {
      setLoading(prev => ({ ...prev, cves: false }));
    }
  }, []);

  const fetchNews = useCallback(async () => {
    try {
      setLoading(prev => ({ ...prev, news: true }));
      const data = await api.get('news');
      setNews(data.articles || []);
      setErrors(prev => ({ ...prev, news: null }));
    } catch (error) {
      setErrors(prev => ({ ...prev, news: error.message }));
    } finally {
      setLoading(prev => ({ ...prev, news: false }));
    }
  }, []);

  useEffect(() => { fetchFeeds(); fetchThreats(); fetchCVEs(); fetchNews(); }, [fetchFeeds, fetchThreats, fetchCVEs, fetchNews]);
  useEffect(() => { const interval = setInterval(fetchThreats, 60000); return () => clearInterval(interval); }, [fetchThreats]);
  useEffect(() => { const interval = setInterval(fetchCVEs, 300000); return () => clearInterval(interval); }, [fetchCVEs]); // Refresh CVEs every 5 minutes
  useEffect(() => { const interval = setInterval(fetchNews, 300000); return () => clearInterval(interval); }, [fetchNews]); // Refresh news every 5 minutes

  const handleUnifiedSearch = async () => {
    if (!unifiedSearchQuery.trim()) return;
    try {
      setSearchLoading(true);
      const results = await api.post('search', { indicator: unifiedSearchQuery.trim() });
      setUnifiedSearchResults(results);
    } catch (error) {
      setErrors(prev => ({ ...prev, search: error.message }));
    } finally {
      setSearchLoading(false);
    }
  };

  const filteredThreats = threats.filter(t => {
    const matchesSearch = t.name?.toLowerCase().includes(searchQuery.toLowerCase()) || t.type?.toLowerCase().includes(searchQuery.toLowerCase()) || t.indicator?.toLowerCase().includes(searchQuery.toLowerCase());
    const matchesSeverity = filterSeverity === 'all' || t.severity === filterSeverity;
    const matchesSource = filterSource === 'all' || t.source === filterSource;

    let matchesDate = true;
    if (filterDateRange !== 'all' && t.timestamp) {
      const now = Date.now();
      const threatTime = t.timestamp;
      switch(filterDateRange) {
        case '1h': matchesDate = (now - threatTime) < 3600000; break;
        case '24h': matchesDate = (now - threatTime) < 86400000; break;
        case '7d': matchesDate = (now - threatTime) < 604800000; break;
        case '30d': matchesDate = (now - threatTime) < 2592000000; break;
        default: matchesDate = true;
      }
    }

    return matchesSearch && matchesSeverity && matchesSource && matchesDate;
  });

  const filteredCVEs = cves.filter(cve => {
    const matchesSearch = cve.cveId?.toLowerCase().includes(cveSearchQuery.toLowerCase()) ||
                         cve.vulnerabilityName?.toLowerCase().includes(cveSearchQuery.toLowerCase()) ||
                         cve.vendorProject?.toLowerCase().includes(cveSearchQuery.toLowerCase()) ||
                         cve.product?.toLowerCase().includes(cveSearchQuery.toLowerCase());

    const matchesRansomware = !filterRansomware || cve.knownRansomwareCampaignUse === 'Known';

    let matchesCriticality = true;
    if (filterCVECriticality !== 'all') {
      const today = new Date();
      const dueDate = new Date(cve.dueDate);
      const daysUntilDue = Math.ceil((dueDate - today) / (1000 * 60 * 60 * 24));

      switch(filterCVECriticality) {
        case 'overdue': matchesCriticality = daysUntilDue < 0; break;
        case 'urgent': matchesCriticality = daysUntilDue >= 0 && daysUntilDue <= 7; break;
        case 'high': matchesCriticality = daysUntilDue > 7 && daysUntilDue <= 30; break;
        case 'medium': matchesCriticality = daysUntilDue > 30; break;
        default: matchesCriticality = true;
      }
    }

    return matchesSearch && matchesRansomware && matchesCriticality;
  });

  const filteredNews = news.filter(article => {
    const matchesSearch = article.title?.toLowerCase().includes(newsSearchQuery.toLowerCase()) ||
                         article.description?.toLowerCase().includes(newsSearchQuery.toLowerCase()) ||
                         article.source?.toLowerCase().includes(newsSearchQuery.toLowerCase());

    const matchesCategory = newsCategoryFilter === 'all' || article.category === newsCategoryFilter;

    return matchesSearch && matchesCategory;
  });

  const stats = {
    total: threats.length,
    critical: threats.filter(t => t.severity === 'critical').length,
    high: threats.filter(t => t.severity === 'high').length,
    connectedFeeds: feeds.filter(f => f.status === 'connected').length,
    totalCVEs: cves.length,
    ransomwareCVEs: cves.filter(c => c.knownRansomwareCampaignUse === 'Known').length
  };

  const attackTypeData = React.useMemo(() => {
    const types = {};
    threats.forEach(t => { const type = t.type || 'Other'; types[type] = (types[type] || 0) + 1; });
    const colors = ['#ff4757', '#ffa502', '#2ed573', '#1e90ff', '#a55eea', '#747d8c'];
    return Object.entries(types).map(([name, value], i) => ({ name: name.length > 15 ? name.substring(0, 15) + '...' : name, value, color: colors[i % colors.length] })).sort((a, b) => b.value - a.value).slice(0, 6);
  }, [threats]);

  const formatTime = (ts) => {
    if (!ts) return 'Unknown';
    const diff = Date.now() - ts;
    if (diff < 60000) return 'Just now';
    if (diff < 3600000) return `${Math.floor(diff / 60000)}m ago`;
    if (diff < 86400000) return `${Math.floor(diff / 3600000)}h ago`;
    return new Date(ts).toLocaleDateString();
  };

  const getThreatIcon = (type) => ({ 'Malware URL': '🔗', 'Malicious IP': '🌐', 'Threat Intel Pulse': '📡', 'botnet_cc': '🤖', 'payload_delivery': '📦' }[type] || '⚠️');

  return (
    <div className="min-h-screen bg-slate-950 text-white font-sans">
      <div className="fixed inset-0 pointer-events-none z-50 opacity-[0.03]" style={{ backgroundImage: 'repeating-linear-gradient(0deg, transparent, transparent 2px, rgba(0, 255, 255, 0.1) 2px, rgba(0, 255, 255, 0.1) 4px)' }} />
      
      <header className="border-b border-slate-800 bg-slate-900/50 backdrop-blur-xl sticky top-0 z-40">
        <div className="max-w-[1800px] mx-auto px-6 py-4">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-4">
              <div className="flex items-center gap-2">
                <div className="w-8 h-8 bg-gradient-to-br from-cyan-500 to-blue-600 rounded-lg flex items-center justify-center"><span className="text-lg">🛡️</span></div>
                <div><h1 className="text-lg font-bold tracking-tight">SENTINEL</h1><p className="text-[10px] text-cyan-500 font-mono tracking-widest">THREAT INTELLIGENCE PLATFORM</p></div>
              </div>
              <div className="h-8 w-px bg-slate-700 mx-4" />
              <nav className="flex gap-1">
                {['overview', 'threats', 'cve', 'news', 'search', 'feeds'].map(tab => (
                  <button key={tab} onClick={() => setActiveTab(tab)} className={`px-4 py-2 text-sm font-medium rounded-lg transition-all ${activeTab === tab ? 'bg-cyan-500/20 text-cyan-400 border border-cyan-500/30' : 'text-slate-400 hover:text-white hover:bg-slate-800'}`}>
                    {tab === 'cve' ? 'CVE/KEV' : tab.charAt(0).toUpperCase() + tab.slice(1)}
                    {tab === 'cve' && stats.ransomwareCVEs > 0 && (
                      <span className="ml-2 px-1.5 py-0.5 bg-red-500 text-white text-xs rounded-full font-mono">
                        {stats.ransomwareCVEs}
                      </span>
                    )}
                  </button>
                ))}
              </nav>
            </div>
            <div className="flex items-center gap-4">
              <div className="text-right"><p className="text-xs text-slate-500 font-mono">SYSTEM TIME</p><p className="text-sm font-mono text-cyan-400">{currentTime.toLocaleTimeString()} UTC</p></div>
              <div className="flex items-center gap-2 px-3 py-1.5 bg-emerald-500/10 border border-emerald-500/30 rounded-full"><div className="w-2 h-2 bg-emerald-500 rounded-full animate-pulse" /><span className="text-xs font-mono text-emerald-400">LIVE</span></div>
            </div>
          </div>
        </div>
      </header>

      <main className="max-w-[1800px] mx-auto px-6 py-6">
        {activeTab === 'overview' && (
          <div className="space-y-6">
            <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
              <MetricCard label="Active Threats" value={stats.total} icon="⚠️" loading={loading.threats} />
              <MetricCard label="Critical Alerts" value={stats.critical} icon="🔴" loading={loading.threats} />
              <MetricCard label="High Priority" value={stats.high} icon="🟠" loading={loading.threats} />
              <MetricCard label="Active Feeds" value={`${stats.connectedFeeds}/${feeds.length}`} icon="📡" loading={loading.feeds} />
            </div>

            <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
              <GlowCard className="lg:col-span-2 p-6">
                <div className="flex items-center justify-between mb-4">
                  <div className="flex items-center gap-3">
                    <h2 className="text-lg font-semibold">Live Threat Feed</h2>
                    <div className="flex items-center gap-1.5 px-2 py-0.5 bg-red-500/10 border border-red-500/30 rounded-full"><div className="w-1.5 h-1.5 bg-red-500 rounded-full animate-pulse" /><span className="text-[10px] font-mono text-red-400">REAL-TIME</span></div>
                  </div>
                  <button onClick={fetchThreats} className="text-xs text-cyan-400 hover:text-cyan-300 font-mono"><span className={loading.threats ? 'animate-spin inline-block' : ''}>↻</span> Refresh</button>
                </div>
                {errors.threats ? <ErrorMessage message={errors.threats} onRetry={fetchThreats} /> : loading.threats ? <LoadingSkeleton rows={5} /> : threats.length === 0 ? (
                  <div className="p-8 text-center text-slate-500"><div className="text-4xl mb-3">📭</div><p>No threats found. Configure API keys to fetch real data.</p></div>
                ) : (
                  <div className="space-y-2 max-h-[400px] overflow-y-auto">
                    {threats.slice(0, 10).map(threat => (
                      <div key={threat.id} onClick={() => setSelectedThreat(threat)} className="flex items-center justify-between p-3 bg-slate-800/50 rounded-lg border border-slate-700/50 hover:border-slate-600 cursor-pointer group">
                        <div className="flex items-center gap-4">
                          <div className={`w-10 h-10 rounded-lg flex items-center justify-center text-lg ${threat.severity === 'critical' ? 'bg-red-500/20' : threat.severity === 'high' ? 'bg-orange-500/20' : 'bg-yellow-500/20'}`}>{getThreatIcon(threat.type)}</div>
                          <div><p className="font-medium text-sm group-hover:text-cyan-400">{threat.name?.substring(0, 50) || 'Unknown'}{threat.name?.length > 50 ? '...' : ''}</p><p className="text-xs text-slate-500 font-mono">{threat.source} • {threat.type}</p></div>
                        </div>
                        <div className="flex items-center gap-4"><div className="text-right"><SeverityBadge severity={threat.severity} /><p className="text-[10px] text-slate-500 font-mono mt-1">{formatTime(threat.timestamp)}</p></div><span className="text-slate-600 group-hover:text-slate-400">→</span></div>
                      </div>
                    ))}
                  </div>
                )}
              </GlowCard>

              <GlowCard className="p-6">
                <h2 className="text-lg font-semibold mb-2">Threat Distribution</h2>
                <p className="text-xs text-slate-500 font-mono mb-4">By type</p>
                {loading.threats ? <div className="h-[200px] flex items-center justify-center"><div className="animate-spin text-2xl">⟳</div></div> : attackTypeData.length > 0 ? (
                  <>
                    <ResponsiveContainer width="100%" height={200}>
                      <PieChart><Pie data={attackTypeData} cx="50%" cy="50%" innerRadius={50} outerRadius={80} paddingAngle={2} dataKey="value">{attackTypeData.map((entry, index) => <Cell key={`cell-${index}`} fill={entry.color} />)}</Pie><Tooltip contentStyle={{ backgroundColor: '#1e293b', border: '1px solid #334155', borderRadius: '8px' }} /></PieChart>
                    </ResponsiveContainer>
                    <div className="grid grid-cols-2 gap-2 mt-4">{attackTypeData.map(item => <div key={item.name} className="flex items-center gap-2 text-xs"><span className="w-2 h-2 rounded-full" style={{ backgroundColor: item.color }} /><span className="text-slate-400 truncate">{item.name}</span><span className="text-white font-mono ml-auto">{item.value}</span></div>)}</div>
                  </>
                ) : <div className="h-[200px] flex items-center justify-center text-slate-500">No data available</div>}
              </GlowCard>
            </div>

            <GlowCard className="p-6">
              <h2 className="text-lg font-semibold mb-4">Intelligence Feed Status</h2>
              {loading.feeds ? <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-6 gap-4">{[...Array(6)].map((_, i) => <div key={i} className="p-4 bg-slate-800/50 rounded-lg animate-pulse"><div className="h-4 w-24 bg-slate-700 rounded mb-2" /><div className="h-3 w-16 bg-slate-700 rounded" /></div>)}</div> : (
                <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-6 gap-4">
                  {feeds.map(feed => (
                    <div key={feed.name} className="p-4 bg-slate-800/50 rounded-lg border border-slate-700/50 hover:border-slate-600">
                      <div className="flex items-center gap-2 mb-2"><StatusIndicator status={feed.status} /><span className="font-medium text-sm">{feed.name}</span></div>
                      <p className={`text-xs font-mono ${feed.status === 'connected' ? 'text-emerald-400' : 'text-yellow-400'}`}>{feed.status.replace('_', ' ')}</p>
                      {feed.free && <span className="inline-block mt-2 px-2 py-0.5 text-[10px] font-mono bg-emerald-500/20 text-emerald-400 rounded">FREE</span>}
                    </div>
                  ))}
                </div>
              )}
            </GlowCard>
          </div>
        )}

        {activeTab === 'threats' && (
          <div className="space-y-6">
            <GlowCard className="p-4">
              <div className="space-y-4">
                <div className="flex flex-wrap items-center gap-4">
                  <div className="flex-1 min-w-[300px]"><input type="text" placeholder="Search threats by name, type, or indicator..." value={searchQuery} onChange={(e) => setSearchQuery(e.target.value)} className="w-full px-4 py-2 bg-slate-800 border border-slate-700 rounded-lg text-sm font-mono focus:outline-none focus:border-cyan-500" /></div>
                  <button onClick={() => setShowAdvancedFilters(!showAdvancedFilters)} className="px-4 py-2 bg-slate-800 text-slate-400 border border-slate-700 rounded-lg text-sm font-mono hover:border-cyan-500">
                    {showAdvancedFilters ? '▼' : '▶'} Filters
                  </button>
                  <button onClick={fetchThreats} className="px-4 py-2 bg-cyan-500/20 text-cyan-400 border border-cyan-500/30 rounded-lg text-sm font-mono hover:bg-cyan-500/30">↻ Refresh</button>
                </div>

                {showAdvancedFilters && (
                  <div className="p-4 bg-slate-800/50 rounded-lg border border-slate-700/50 space-y-4">
                    <div>
                      <p className="text-xs text-slate-500 font-mono uppercase mb-2">Severity</p>
                      <div className="flex flex-wrap gap-2">
                        {['all', 'critical', 'high', 'medium', 'low'].map(sev => (
                          <button key={sev} onClick={() => setFilterSeverity(sev)} className={`px-3 py-1.5 text-xs font-mono rounded-lg transition-all ${filterSeverity === sev ? 'bg-cyan-500/20 text-cyan-400 border border-cyan-500/30' : 'bg-slate-800 text-slate-400 border border-slate-700 hover:border-slate-600'}`}>{sev.toUpperCase()}</button>
                        ))}
                      </div>
                    </div>

                    <div>
                      <p className="text-xs text-slate-500 font-mono uppercase mb-2">Source</p>
                      <div className="flex flex-wrap gap-2">
                        {['all', ...Array.from(new Set(threats.map(t => t.source)))].map(src => (
                          <button key={src} onClick={() => setFilterSource(src)} className={`px-3 py-1.5 text-xs font-mono rounded-lg transition-all ${filterSource === src ? 'bg-cyan-500/20 text-cyan-400 border border-cyan-500/30' : 'bg-slate-800 text-slate-400 border border-slate-700 hover:border-slate-600'}`}>{src.toUpperCase()}</button>
                        ))}
                      </div>
                    </div>

                    <div>
                      <p className="text-xs text-slate-500 font-mono uppercase mb-2">Time Range</p>
                      <div className="flex flex-wrap gap-2">
                        {[
                          { value: 'all', label: 'ALL TIME' },
                          { value: '1h', label: 'LAST HOUR' },
                          { value: '24h', label: 'LAST 24H' },
                          { value: '7d', label: 'LAST 7 DAYS' },
                          { value: '30d', label: 'LAST 30 DAYS' }
                        ].map(range => (
                          <button key={range.value} onClick={() => setFilterDateRange(range.value)} className={`px-3 py-1.5 text-xs font-mono rounded-lg transition-all ${filterDateRange === range.value ? 'bg-cyan-500/20 text-cyan-400 border border-cyan-500/30' : 'bg-slate-800 text-slate-400 border border-slate-700 hover:border-slate-600'}`}>{range.label}</button>
                        ))}
                      </div>
                    </div>

                    <div className="flex items-center justify-between pt-2 border-t border-slate-700">
                      <p className="text-xs text-slate-500 font-mono">Showing {filteredThreats.length} of {threats.length} threats</p>
                      <button onClick={() => { setSearchQuery(''); setFilterSeverity('all'); setFilterSource('all'); setFilterDateRange('all'); }} className="text-xs text-cyan-400 hover:text-cyan-300 font-mono">Clear All Filters</button>
                    </div>
                  </div>
                )}

                {threatFeedErrors.length > 0 && (
                  <div className="p-3 bg-amber-500/10 border border-amber-500/30 rounded-lg space-y-2">
                    <div className="flex items-center gap-2 text-xs font-mono text-amber-300 uppercase">
                      <span>Source availability</span>
                      <span className="px-2 py-0.5 bg-amber-500/20 rounded">{threatFeedErrors.length}</span>
                    </div>
                    <div className="space-y-1 text-sm text-amber-200">
                      {threatFeedErrors.map((issue, idx) => (
                        <div key={`${issue.source}-${idx}`} className="flex items-center justify-between gap-2">
                          <span className="font-semibold">{issue.source}</span>
                          <span className="text-amber-100 text-xs text-right">{issue.error}</span>
                        </div>
                      ))}
                    </div>
                  </div>
                )}
              </div>
            </GlowCard>
            <GlowCard className="overflow-hidden">
              {errors.threats ? <ErrorMessage message={errors.threats} onRetry={fetchThreats} /> : loading.threats ? <div className="p-6"><LoadingSkeleton rows={8} /></div> : (
                <div className="overflow-x-auto">
                  <table className="w-full">
                    <thead className="bg-slate-800/50 border-b border-slate-700"><tr><th className="px-6 py-4 text-left text-xs font-mono text-slate-500 uppercase">Threat</th><th className="px-6 py-4 text-left text-xs font-mono text-slate-500 uppercase">Type</th><th className="px-6 py-4 text-left text-xs font-mono text-slate-500 uppercase">Severity</th><th className="px-6 py-4 text-left text-xs font-mono text-slate-500 uppercase">Source</th><th className="px-6 py-4 text-left text-xs font-mono text-slate-500 uppercase">Time</th></tr></thead>
                    <tbody className="divide-y divide-slate-800">
                      {filteredThreats.slice(0, 50).map(threat => (
                        <tr key={threat.id} className="hover:bg-slate-800/30 cursor-pointer" onClick={() => setSelectedThreat(threat)}>
                          <td className="px-6 py-4"><div className="flex items-center gap-3"><span className="text-lg">{getThreatIcon(threat.type)}</span><div><p className="font-medium text-sm">{threat.name?.substring(0, 40)}</p><p className="text-xs text-slate-500 font-mono">{threat.id}</p></div></div></td>
                          <td className="px-6 py-4 text-sm text-slate-400">{threat.type}</td>
                          <td className="px-6 py-4"><SeverityBadge severity={threat.severity} /></td>
                          <td className="px-6 py-4 text-sm text-slate-400">{threat.source}</td>
                          <td className="px-6 py-4 text-sm text-slate-500 font-mono">{formatTime(threat.timestamp)}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                  {filteredThreats.length === 0 && <div className="p-12 text-center text-slate-500">No threats match your filters</div>}
                </div>
              )}
            </GlowCard>
          </div>
        )}

        {activeTab === 'cve' && (
          <div className="space-y-6">
            <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
              <MetricCard label="Total KEVs" value={stats.totalCVEs} icon="💥" loading={loading.cves} />
              <MetricCard label="Ransomware" value={stats.ransomwareCVEs} icon="🔒" loading={loading.cves} />
              <MetricCard label="Filtered" value={filteredCVEs.length} icon="🔍" loading={loading.cves} />
              <MetricCard label="CISA Catalog" value={stats.totalCVEs} icon="🏛️" loading={loading.cves} />
            </div>

            <GlowCard className="p-4">
              <div className="space-y-4">
                <div className="flex flex-wrap items-center gap-4">
                  <div className="flex-1 min-w-[300px]">
                    <input
                      type="text"
                      placeholder="Search CVE ID, vulnerability, vendor, or product..."
                      value={cveSearchQuery}
                      onChange={(e) => setCveSearchQuery(e.target.value)}
                      className="w-full px-4 py-2 bg-slate-800 border border-slate-700 rounded-lg text-sm font-mono focus:outline-none focus:border-cyan-500"
                    />
                  </div>
                  <button
                    onClick={fetchCVEs}
                    className="px-4 py-2 bg-cyan-500/20 text-cyan-400 border border-cyan-500/30 rounded-lg text-sm font-mono hover:bg-cyan-500/30"
                  >
                    ↻ Refresh
                  </button>
                </div>

                <div className="p-4 bg-slate-800/50 rounded-lg border border-slate-700/50 space-y-4">
                  <div>
                    <p className="text-xs text-slate-500 font-mono uppercase mb-2">Criticality (By Due Date)</p>
                    <div className="flex flex-wrap gap-2">
                      {[
                        { value: 'all', label: 'ALL' },
                        { value: 'overdue', label: 'OVERDUE' },
                        { value: 'urgent', label: 'URGENT (≤7 days)' },
                        { value: 'high', label: 'HIGH (≤30 days)' },
                        { value: 'medium', label: 'MEDIUM (>30 days)' }
                      ].map(crit => (
                        <button
                          key={crit.value}
                          onClick={() => setFilterCVECriticality(crit.value)}
                          className={`px-3 py-1.5 text-xs font-mono rounded-lg transition-all ${
                            filterCVECriticality === crit.value
                              ? 'bg-cyan-500/20 text-cyan-400 border border-cyan-500/30'
                              : 'bg-slate-800 text-slate-400 border border-slate-700 hover:border-slate-600'
                          }`}
                        >
                          {crit.label}
                        </button>
                      ))}
                    </div>
                  </div>

                  <div>
                    <label className="flex items-center gap-2 cursor-pointer">
                      <input
                        type="checkbox"
                        checked={filterRansomware}
                        onChange={(e) => setFilterRansomware(e.target.checked)}
                        className="w-4 h-4 rounded border-slate-700 bg-slate-800 text-cyan-500 focus:ring-cyan-500 focus:ring-offset-slate-900"
                      />
                      <span className="text-sm text-slate-300">Show only ransomware-linked CVEs</span>
                      <span className="px-2 py-0.5 bg-purple-500/20 text-purple-400 border border-purple-500/30 rounded text-xs font-mono">
                        🔒 RANSOMWARE
                      </span>
                    </label>
                  </div>

                  <div className="flex items-center justify-between pt-2 border-t border-slate-700">
                    <p className="text-xs text-slate-500 font-mono">
                      Showing {filteredCVEs.length} of {cves.length} CVEs
                    </p>
                    <button
                      onClick={() => {
                        setCveSearchQuery('');
                        setFilterCVECriticality('all');
                        setFilterRansomware(false);
                      }}
                      className="text-xs text-cyan-400 hover:text-cyan-300 font-mono"
                    >
                      Clear All Filters
                    </button>
                  </div>
                </div>
              </div>
            </GlowCard>

            <GlowCard className="overflow-hidden">
              {errors.cves ? (
                <ErrorMessage message={errors.cves} onRetry={fetchCVEs} />
              ) : loading.cves ? (
                <div className="p-6"><LoadingSkeleton rows={8} /></div>
              ) : (
                <div className="overflow-x-auto">
                  <table className="w-full">
                    <thead className="bg-slate-800/50 border-b border-slate-700">
                      <tr>
                        <th className="px-6 py-4 text-left text-xs font-mono text-slate-500 uppercase">CVE ID</th>
                        <th className="px-6 py-4 text-left text-xs font-mono text-slate-500 uppercase">Vulnerability</th>
                        <th className="px-6 py-4 text-left text-xs font-mono text-slate-500 uppercase">Vendor / Product</th>
                        <th className="px-6 py-4 text-left text-xs font-mono text-slate-500 uppercase">Due Date</th>
                        <th className="px-6 py-4 text-left text-xs font-mono text-slate-500 uppercase">Status</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-slate-800">
                      {filteredCVEs.slice(0, 50).map(cve => {
                        const today = new Date();
                        const dueDate = new Date(cve.dueDate);
                        const daysUntilDue = Math.ceil((dueDate - today) / (1000 * 60 * 60 * 24));
                        const isOverdue = daysUntilDue < 0;
                        const isUrgent = daysUntilDue >= 0 && daysUntilDue <= 7;

                        return (
                          <tr
                            key={cve.cveId}
                            className="hover:bg-slate-800/30 cursor-pointer"
                            onClick={() => setSelectedCVE(cve)}
                          >
                            <td className="px-6 py-4">
                              <div className="flex items-center gap-2 flex-wrap">
                                <span className="px-2 py-0.5 bg-red-500/20 text-red-400 border border-red-500/30 rounded text-xs font-mono font-semibold">
                                  🚨 KEV
                                </span>
                                <span className="text-sm font-mono text-cyan-400 font-semibold">{cve.cveId}</span>
                                {cve.knownRansomwareCampaignUse === 'Known' && (
                                  <span className="px-1.5 py-0.5 bg-purple-500/20 text-purple-400 border border-purple-500/30 rounded text-xs">
                                    🔒 RANSOMWARE
                                  </span>
                                )}
                              </div>
                            </td>
                            <td className="px-6 py-4">
                              <p className="font-medium text-sm max-w-md truncate">{cve.vulnerabilityName}</p>
                              <p className="text-xs text-slate-500 mt-1 max-w-md truncate">{cve.shortDescription}</p>
                            </td>
                            <td className="px-6 py-4">
                              <p className="text-sm text-slate-300">{cve.vendorProject}</p>
                              <p className="text-xs text-slate-500">{cve.product}</p>
                            </td>
                            <td className="px-6 py-4">
                              <p className={`text-sm font-mono ${
                                isOverdue ? 'text-red-400 font-bold' : isUrgent ? 'text-orange-400 font-semibold' : 'text-slate-400'
                              }`}>
                                {cve.dueDate}
                              </p>
                              <p className="text-xs text-slate-500 mt-1">
                                {isOverdue ? `${Math.abs(daysUntilDue)} days overdue` : `${daysUntilDue} days left`}
                              </p>
                            </td>
                            <td className="px-6 py-4">
                              {isOverdue ? (
                                <span className="px-2 py-1 bg-red-500/20 text-red-400 border border-red-500/30 rounded text-xs font-mono">
                                  OVERDUE
                                </span>
                              ) : isUrgent ? (
                                <span className="px-2 py-1 bg-orange-500/20 text-orange-400 border border-orange-500/30 rounded text-xs font-mono animate-pulse">
                                  URGENT
                                </span>
                              ) : daysUntilDue <= 30 ? (
                                <span className="px-2 py-1 bg-yellow-500/20 text-yellow-400 border border-yellow-500/30 rounded text-xs font-mono">
                                  HIGH
                                </span>
                              ) : (
                                <span className="px-2 py-1 bg-blue-500/20 text-blue-400 border border-blue-500/30 rounded text-xs font-mono">
                                  MEDIUM
                                </span>
                              )}
                            </td>
                          </tr>
                        );
                      })}
                    </tbody>
                  </table>
                  {filteredCVEs.length === 0 && (
                    <div className="p-12 text-center text-slate-500">No CVEs match your filters</div>
                  )}
                </div>
              )}
            </GlowCard>
          </div>
        )}

        {activeTab === 'search' && (
          <div className="space-y-6">
            <GlowCard className="p-6">
              <h2 className="text-xl font-semibold mb-2">Unified Threat Search</h2>
              <p className="text-slate-500 mb-6">Search across all connected intelligence feeds</p>
              <div className="flex gap-4 mb-6">
                <input type="text" value={unifiedSearchQuery} onChange={(e) => setUnifiedSearchQuery(e.target.value)} onKeyDown={(e) => e.key === 'Enter' && handleUnifiedSearch()} placeholder="Enter IP, domain, hash, or URL..." className="flex-1 px-4 py-3 bg-slate-800 border border-slate-700 rounded-lg font-mono focus:outline-none focus:border-cyan-500" />
                <button onClick={handleUnifiedSearch} disabled={searchLoading || !unifiedSearchQuery.trim()} className="px-6 py-3 bg-cyan-500 hover:bg-cyan-400 disabled:bg-slate-700 disabled:cursor-not-allowed text-slate-900 font-medium rounded-lg flex items-center gap-2">
                  {searchLoading ? <><span className="animate-spin">⟳</span> Searching...</> : <>🔍 Search All Feeds</>}
                </button>
              </div>
              <div className="flex flex-wrap gap-2 text-xs text-slate-500"><span>Examples:</span><button onClick={() => setUnifiedSearchQuery('8.8.8.8')} className="text-cyan-400 hover:underline">8.8.8.8</button><button onClick={() => setUnifiedSearchQuery('google.com')} className="text-cyan-400 hover:underline">google.com</button></div>
            </GlowCard>
            {unifiedSearchResults && (
              <GlowCard className="p-6">
                <div className="flex items-center justify-between mb-4"><h3 className="font-semibold">Results for: <span className="text-cyan-400 font-mono">{unifiedSearchResults.indicator}</span></h3><span className="text-xs text-slate-500 font-mono">{unifiedSearchResults.sources?.length || 0} sources</span></div>
                <div className="space-y-4">
                  {unifiedSearchResults.sources?.map((source, idx) => (
                    <div key={idx} className="p-4 bg-slate-800/50 rounded-lg border border-slate-700/50">
                      <div className="flex items-center gap-2 mb-3"><span className="font-semibold text-cyan-400">{source.source}</span>{source.error && <span className="px-2 py-0.5 text-xs bg-red-500/20 text-red-400 rounded">Error</span>}</div>
                      {source.error ? <p className="text-red-400 text-sm">{source.error}</p> : (
                        <div className="grid grid-cols-2 md:grid-cols-4 gap-4 text-sm">
                          {source.abuseScore !== undefined && <div><p className="text-slate-500 text-xs">Abuse Score</p><p className={`font-mono ${source.abuseScore > 50 ? 'text-red-400' : 'text-emerald-400'}`}>{source.abuseScore}%</p></div>}
                          {source.malicious !== undefined && <div><p className="text-slate-500 text-xs">Malicious</p><p className={`font-mono ${source.malicious > 0 ? 'text-red-400' : 'text-emerald-400'}`}>{source.malicious} / {source.totalEngines}</p></div>}
                          {source.pulseCount !== undefined && <div><p className="text-slate-500 text-xs">OTX Pulses</p><p className="font-mono text-yellow-400">{source.pulseCount}</p></div>}
                          {source.country && <div><p className="text-slate-500 text-xs">Country</p><p>{source.country}</p></div>}
                          {source.found === false && <div className="col-span-4"><p className="text-slate-500">No records found</p></div>}
                        </div>
                      )}
                    </div>
                  ))}
                </div>
              </GlowCard>
            )}
          </div>
        )}

        {activeTab === 'news' && (
          <div className="space-y-6">
            <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
              <MetricCard label="Total Articles" value={news.length} icon="📰" loading={loading.news} />
              <MetricCard label="News Sources" value={filteredNews.filter((_, i, arr) => arr.findIndex(a => a.source === _.source) === i).length} icon="📡" loading={loading.news} />
              <MetricCard label="Advisories" value={news.filter(n => n.category === 'advisory').length} icon="🏛️" loading={loading.news} />
              <MetricCard label="Latest Update" value={news[0] ? new Date(news[0].publishedAt).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }) : '--:--'} icon="⏱️" loading={loading.news} />
            </div>

            <GlowCard className="p-4">
              <div className="space-y-4">
                <div className="flex flex-wrap items-center gap-4">
                  <div className="flex-1 min-w-[300px]">
                    <input
                      type="text"
                      placeholder="Search news by title or description..."
                      value={newsSearchQuery}
                      onChange={(e) => setNewsSearchQuery(e.target.value)}
                      className="w-full px-4 py-2 bg-slate-800 border border-slate-700 rounded-lg text-sm focus:outline-none focus:border-cyan-500"
                    />
                  </div>
                  <button
                    onClick={fetchNews}
                    className="px-4 py-2 bg-cyan-500/20 text-cyan-400 border border-cyan-500/30 rounded-lg text-sm font-mono hover:bg-cyan-500/30"
                  >
                    ↻ Refresh
                  </button>
                </div>

                <div className="p-4 bg-slate-800/50 rounded-lg border border-slate-700/50 space-y-4">
                  <div>
                    <p className="text-xs text-slate-500 font-mono uppercase mb-2">Category</p>
                    <div className="flex flex-wrap gap-2">
                      {[
                        { value: 'all', label: 'ALL', icon: '📰' },
                        { value: 'news', label: 'NEWS', icon: '📢' },
                        { value: 'blog', label: 'BLOGS', icon: '✍️' },
                        { value: 'advisory', label: 'ADVISORIES', icon: '🏛️' }
                      ].map(cat => (
                        <button
                          key={cat.value}
                          onClick={() => setNewsCategoryFilter(cat.value)}
                          className={`px-3 py-1.5 text-xs font-mono rounded-lg transition-all ${
                            newsCategoryFilter === cat.value
                              ? 'bg-cyan-500/20 text-cyan-400 border border-cyan-500/30'
                              : 'bg-slate-800 text-slate-400 border border-slate-700 hover:border-slate-600'
                          }`}
                        >
                          {cat.icon} {cat.label}
                        </button>
                      ))}
                    </div>
                  </div>

                  <div className="flex items-center justify-between pt-2 border-t border-slate-700">
                    <p className="text-xs text-slate-500 font-mono">
                      Showing {filteredNews.length} of {news.length} articles
                    </p>
                    <button
                      onClick={() => {
                        setNewsSearchQuery('');
                        setNewsCategoryFilter('all');
                      }}
                      className="px-3 py-1 bg-slate-700 hover:bg-slate-600 rounded text-xs text-slate-400"
                    >
                      Clear Filters
                    </button>
                  </div>
                </div>
              </div>
            </GlowCard>

            {loading.news ? (
              <div className="flex justify-center items-center py-12">
                <div className="text-center space-y-2">
                  <div className="inline-block animate-spin text-4xl">⚡</div>
                  <p className="text-slate-400 font-mono text-sm">Loading cybersecurity news...</p>
                </div>
              </div>
            ) : errors.news ? (
              <div className="p-6 bg-red-500/10 border border-red-500/30 rounded-lg">
                <p className="text-red-400">⚠️ Error loading news: {errors.news}</p>
              </div>
            ) : filteredNews.length === 0 ? (
              <div className="p-12 text-center">
                <p className="text-slate-400 text-lg mb-2">📰 No articles found</p>
                <p className="text-slate-500 text-sm">Try adjusting your filters or search query</p>
              </div>
            ) : (
              <div className="space-y-3">
                {filteredNews.map((article, index) => (
                  <GlowCard key={index} className="p-4 hover:border-cyan-500/50 transition-all cursor-pointer group">
                    <a href={article.link} target="_blank" rel="noopener noreferrer" className="block">
                      <div className="flex items-start gap-4">
                        <div className="flex-shrink-0">
                          <div className="w-12 h-12 bg-gradient-to-br from-cyan-500/20 to-blue-500/20 border border-cyan-500/30 rounded-lg flex items-center justify-center">
                            <span className="text-2xl">
                              {article.category === 'advisory' ? '🏛️' : article.category === 'blog' ? '✍️' : '📰'}
                            </span>
                          </div>
                        </div>
                        <div className="flex-1 min-w-0">
                          <div className="flex items-center gap-2 mb-2">
                            <span className="px-2 py-0.5 bg-cyan-500/20 text-cyan-400 border border-cyan-500/30 rounded text-xs font-mono">
                              {article.source}
                            </span>
                            <span className="px-2 py-0.5 bg-slate-700 text-slate-400 rounded text-xs font-mono uppercase">
                              {article.category}
                            </span>
                            <span className="text-xs text-slate-500 font-mono">
                              {new Date(article.publishedAt).toLocaleString()}
                            </span>
                          </div>
                          <h3 className="text-white font-semibold mb-2 group-hover:text-cyan-400 transition-colors line-clamp-2">
                            {article.title}
                          </h3>
                          {article.description && (
                            <p className="text-sm text-slate-400 line-clamp-2">{article.description}</p>
                          )}
                        </div>
                        <div className="flex-shrink-0">
                          <span className="text-slate-500 group-hover:text-cyan-400 transition-colors">→</span>
                        </div>
                      </div>
                    </a>
                  </GlowCard>
                ))}
              </div>
            )}

            <div className="p-4 bg-slate-800/50 rounded-lg border border-slate-700/50">
              <p className="text-xs text-slate-500 font-mono uppercase mb-2">News Sources</p>
              <div className="text-sm text-slate-400 space-y-1">
                <p>• The Hacker News - Breaking cybersecurity news</p>
                <p>• Bleeping Computer - Technology and security alerts</p>
                <p>• Krebs on Security - In-depth security investigation</p>
                <p>• CISA Alerts - Official US government advisories</p>
                <p>• Threatpost - Enterprise security news</p>
                <p>• SecurityWeek - Security news and analysis</p>
                <p>• Dark Reading - Cybersecurity intelligence</p>
                <p className="text-xs text-slate-600 mt-2">Note: News updates every 5 minutes. Twitter/X feed requires API access (not publicly available).</p>
              </div>
            </div>
          </div>
        )}

        {activeTab === 'feeds' && (
          <div className="space-y-6">
            <div className="flex items-center justify-between"><div><h2 className="text-xl font-semibold">Intelligence Feeds</h2><p className="text-sm text-slate-500">Configure threat intelligence sources</p></div><button onClick={fetchFeeds} className="px-4 py-2 bg-slate-700 hover:bg-slate-600 rounded-lg text-sm">↻ Refresh</button></div>
            {errors.feeds ? <ErrorMessage message={errors.feeds} onRetry={fetchFeeds} /> : loading.feeds ? <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">{[...Array(6)].map((_, i) => <div key={i} className="p-6 bg-slate-900 border border-slate-700 rounded-lg animate-pulse"><div className="h-6 w-32 bg-slate-700 rounded mb-4" /><div className="h-4 w-full bg-slate-700 rounded" /></div>)}</div> : (
              <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
                {feeds.map(feed => (
                  <GlowCard key={feed.name} className="p-6">
                    <div className="flex items-start justify-between mb-4">
                      <div className="flex items-center gap-3"><StatusIndicator status={feed.status} /><div><h3 className="font-semibold">{feed.name}</h3><a href={feed.docs} target="_blank" rel="noopener noreferrer" className="text-xs text-cyan-400 hover:underline">Documentation →</a></div></div>
                      {feed.free && <span className="px-2 py-0.5 text-[10px] font-mono bg-emerald-500/20 text-emerald-400 border border-emerald-500/30 rounded">FREE</span>}
                    </div>
                    <div className="space-y-3"><div className="flex justify-between text-sm"><span className="text-slate-500">Status</span><span className={`font-mono ${feed.status === 'connected' ? 'text-emerald-400' : 'text-yellow-400'}`}>{feed.status.replace(/_/g, ' ').toUpperCase()}</span></div><div className="flex justify-between text-sm"><span className="text-slate-500">Rate Limit</span><span className="font-mono text-slate-300">{feed.rateLimit}</span></div></div>
                    <div className="mt-4 pt-4 border-t border-slate-700">{feed.status === 'connected' ? <div className="text-center text-xs text-emerald-400 font-mono">✓ Active</div> : <p className="text-xs text-slate-500">Add API key in Vercel to enable</p>}</div>
                  </GlowCard>
                ))}
              </div>
            )}
            <GlowCard className="p-6">
              <h3 className="font-semibold mb-4">Quick Setup</h3>
              <div className="space-y-4 text-sm">
                <div className="p-4 bg-slate-800/50 rounded-lg"><p className="font-mono text-cyan-400 mb-2">1. Get Free API Keys</p><ul className="text-slate-400 space-y-1 ml-4"><li>• <a href="https://www.abuseipdb.com/register" target="_blank" rel="noopener noreferrer" className="text-cyan-400 hover:underline">AbuseIPDB</a></li><li>• <a href="https://otx.alienvault.com/" target="_blank" rel="noopener noreferrer" className="text-cyan-400 hover:underline">AlienVault OTX</a></li><li>• <a href="https://www.virustotal.com/gui/join-us" target="_blank" rel="noopener noreferrer" className="text-cyan-400 hover:underline">VirusTotal</a></li><li>• <a href="https://account.shodan.io/register" target="_blank" rel="noopener noreferrer" className="text-cyan-400 hover:underline">Shodan</a></li></ul></div>
                <div className="p-4 bg-slate-800/50 rounded-lg"><p className="font-mono text-cyan-400 mb-2">2. Add to Vercel</p><p className="text-slate-400">Settings → Environment Variables</p></div>
                <div className="p-4 bg-slate-800/50 rounded-lg"><p className="font-mono text-cyan-400 mb-2">3. Redeploy</p><p className="text-slate-400">Deployments → Redeploy</p></div>
              </div>
            </GlowCard>
          </div>
        )}
      </main>

      {selectedThreat && (() => {
        const mitreData = mapThreatToMitre(selectedThreat);
        const mitigations = generateMitigations(selectedThreat);
        const remediation = generateRemediation(selectedThreat);
        const relatedCVEs = mapThreatToCVEs(selectedThreat);

        return (
          <div className="fixed inset-0 bg-slate-950/80 backdrop-blur-sm z-50 flex items-center justify-center p-6 overflow-y-auto">
            <div className="bg-slate-900 border border-slate-700 rounded-xl max-w-6xl w-full my-8">
              <div className="sticky top-0 bg-slate-900 border-b border-slate-700 p-6 flex items-start justify-between z-10">
                <div>
                  <div className="flex items-center gap-3 mb-2">
                    <SeverityBadge severity={selectedThreat.severity} />
                    <span className="text-xs text-slate-500 font-mono">{selectedThreat.source}</span>
                    <span className="text-xs text-slate-500 font-mono">ID: {selectedThreat.id}</span>
                  </div>
                  <h2 className="text-xl font-bold">{selectedThreat.name}</h2>
                  <p className="text-sm text-slate-400 mt-1">{selectedThreat.type}</p>
                </div>
                <button onClick={() => { setSelectedThreat(null); setThreatDetailTab('overview'); }} className="p-2 hover:bg-slate-800 rounded-lg text-slate-400 hover:text-white">✕</button>
              </div>

              <div className="border-b border-slate-700">
                <nav className="flex px-6 overflow-x-auto">
                  {[
                    { id: 'overview', label: 'Overview', icon: '📊' },
                    { id: 'cve', label: 'CVE/KEV', icon: '💥', badge: relatedCVEs.length > 0 ? relatedCVEs.length : null },
                    { id: 'mitre', label: 'MITRE ATT&CK', icon: '🎯' },
                    { id: 'mitigations', label: 'Mitigations', icon: '🛡️' },
                    { id: 'remediation', label: 'Remediation', icon: '🔧' }
                  ].map(tab => (
                    <button
                      key={tab.id}
                      onClick={() => setThreatDetailTab(tab.id)}
                      className={`px-4 py-3 text-sm font-medium border-b-2 transition-colors flex items-center gap-2 ${
                        threatDetailTab === tab.id
                          ? 'border-cyan-500 text-cyan-400'
                          : 'border-transparent text-slate-400 hover:text-white hover:border-slate-600'
                      }`}
                    >
                      <span>{tab.icon}</span>
                      <span>{tab.label}</span>
                      {tab.badge && (
                        <span className="px-1.5 py-0.5 bg-red-500 text-white text-xs rounded-full font-mono">
                          {tab.badge}
                        </span>
                      )}
                    </button>
                  ))}
                </nav>
              </div>

              <div className="p-6 max-h-[60vh] overflow-y-auto">
                {threatDetailTab === 'overview' && (
                  <div className="space-y-6">
                    {selectedThreat.indicator && (
                      <div className="p-4 bg-slate-800/50 rounded-lg border border-slate-700/50">
                        <p className="text-xs text-slate-500 font-mono uppercase mb-2">Indicator of Compromise (IOC)</p>
                        <p className="font-mono text-cyan-400 break-all text-lg">{selectedThreat.indicator}</p>
                      </div>
                    )}

                    <div className="grid grid-cols-2 gap-4">
                      <div className="p-4 bg-slate-800/50 rounded-lg border border-slate-700/50">
                        <p className="text-xs text-slate-500 font-mono uppercase mb-2">First Seen</p>
                        <p className="text-white">{selectedThreat.timestamp ? new Date(selectedThreat.timestamp).toLocaleString() : 'Unknown'}</p>
                      </div>
                      {selectedThreat.confidence && (
                        <div className="p-4 bg-slate-800/50 rounded-lg border border-slate-700/50">
                          <p className="text-xs text-slate-500 font-mono uppercase mb-2">Confidence Level</p>
                          <p className="text-white">{selectedThreat.confidence}%</p>
                        </div>
                      )}
                      {selectedThreat.country && (
                        <div className="p-4 bg-slate-800/50 rounded-lg border border-slate-700/50">
                          <p className="text-xs text-slate-500 font-mono uppercase mb-2">Country</p>
                          <p className="text-white">{selectedThreat.country}</p>
                        </div>
                      )}
                      {selectedThreat.abuseScore && (
                        <div className="p-4 bg-slate-800/50 rounded-lg border border-slate-700/50">
                          <p className="text-xs text-slate-500 font-mono uppercase mb-2">Abuse Score</p>
                          <p className={`font-bold ${selectedThreat.abuseScore >= 90 ? 'text-red-400' : selectedThreat.abuseScore >= 70 ? 'text-orange-400' : 'text-yellow-400'}`}>
                            {selectedThreat.abuseScore}%
                          </p>
                        </div>
                      )}
                    </div>

                    {selectedThreat.description && (
                      <div className="p-4 bg-slate-800/50 rounded-lg border border-slate-700/50">
                        <p className="text-xs text-slate-500 font-mono uppercase mb-2">Description</p>
                        <p className="text-slate-300 text-sm">{selectedThreat.description}</p>
                      </div>
                    )}

                    {selectedThreat.tags?.length > 0 && (
                      <div>
                        <h3 className="text-sm font-mono text-slate-500 uppercase mb-3">Tags</h3>
                        <div className="flex flex-wrap gap-2">
                          {selectedThreat.tags.map((tag, i) => (
                            <span key={i} className="px-3 py-1 bg-purple-500/20 text-purple-400 border border-purple-500/30 rounded-full text-sm">
                              {tag}
                            </span>
                          ))}
                        </div>
                      </div>
                    )}

                    <div className="flex gap-3 pt-4 border-t border-slate-700">
                      <button
                        onClick={() => navigator.clipboard.writeText(selectedThreat.indicator || selectedThreat.id)}
                        className="flex-1 px-4 py-2 bg-cyan-500/20 text-cyan-400 border border-cyan-500/30 rounded-lg font-medium hover:bg-cyan-500/30"
                      >
                        📋 Copy Indicator
                      </button>
                      <button
                        onClick={() => {
                          setUnifiedSearchQuery(selectedThreat.indicator);
                          setActiveTab('search');
                          setSelectedThreat(null);
                        }}
                        className="flex-1 px-4 py-2 bg-slate-700 text-white rounded-lg font-medium hover:bg-slate-600"
                      >
                        🔍 Deep Search
                      </button>
                    </div>
                  </div>
                )}

                {threatDetailTab === 'cve' && (
                  <div className="space-y-6">
                    {relatedCVEs.length === 0 ? (
                      <div className="p-8 text-center">
                        <div className="text-6xl mb-4">🔍</div>
                        <h3 className="text-lg font-semibold text-slate-400 mb-2">No CVEs Detected</h3>
                        <p className="text-sm text-slate-500">
                          No specific CVE vulnerabilities have been associated with this threat indicator.
                        </p>
                        <p className="text-xs text-slate-600 mt-4">
                          This may indicate a zero-day threat, generic malware, or the threat is not related to a known vulnerability.
                        </p>
                      </div>
                    ) : (
                      <>
                        <div className="p-4 bg-gradient-to-r from-red-500/10 to-rose-500/10 border border-red-500/30 rounded-lg">
                          <h3 className="text-lg font-semibold text-red-400 mb-2">💥 Related Vulnerabilities (CVE/KEV)</h3>
                          <p className="text-sm text-slate-400">
                            This threat is associated with {relatedCVEs.length} known vulnerabilit{relatedCVEs.length === 1 ? 'y' : 'ies'}.
                            {relatedCVEs.some(cve => cve.exploited) && <span className="text-red-400 font-semibold"> ⚠️ Actively exploited in the wild.</span>}
                          </p>
                        </div>

                        {relatedCVEs.map((cve, idx) => {
                          const breakdown = generateVulnerabilityBreakdown(cve);
                          const cveMitigation = generateCVEMitigation(cve);
                          const cvssFormat = formatCVSS(cve.cvss);
                          const links = getCVELinks(cve.cveId);
                          const priorities = getCVEPriority(cve);

                          return (
                            <div key={idx} className="border border-slate-700 rounded-lg overflow-hidden">
                              {/* CVE Header */}
                              <div className="bg-slate-800/80 p-4 border-b border-slate-700">
                                <div className="flex items-start justify-between mb-3">
                                  <div>
                                    <div className="flex items-center gap-2 mb-2">
                                      <h4 className="text-xl font-bold text-white font-mono">{cve.cveId}</h4>
                                      <span className={`px-2 py-1 rounded text-xs font-mono border ${cvssFormat.bg} ${cvssFormat.text} ${cvssFormat.border}`}>
                                        CVSS {cvssFormat.score} - {cvssFormat.severity}
                                      </span>
                                    </div>
                                    <p className="text-sm text-slate-300 mb-2">{cve.vulnerabilityName}</p>
                                    <p className="text-xs text-slate-500">
                                      {cve.vendorProject} - {cve.product}
                                    </p>
                                  </div>
                                </div>

                                {/* Priority Badges */}
                                {priorities.length > 0 && (
                                  <div className="flex flex-wrap gap-2 mb-3">
                                    {priorities.map((priority, i) => (
                                      <span
                                        key={i}
                                        className={`px-3 py-1 text-xs font-mono border rounded-full animate-pulse
                                          ${priority.color === 'red' ? 'bg-red-500/20 text-red-400 border-red-500/50' : ''}
                                          ${priority.color === 'orange' ? 'bg-orange-500/20 text-orange-400 border-orange-500/50' : ''}
                                          ${priority.color === 'purple' ? 'bg-purple-500/20 text-purple-400 border-purple-500/50' : ''}
                                        `}
                                      >
                                        {priority.icon} {priority.label}
                                      </span>
                                    ))}
                                  </div>
                                )}

                                {/* Timeline */}
                                <div className="flex gap-4 text-xs">
                                  <div><span className="text-slate-500">Added to KEV:</span> <span className="text-slate-300">{cve.dateAdded}</span></div>
                                  <div><span className="text-slate-500">Due Date:</span> <span className="text-red-400 font-semibold">{cve.dueDate}</span></div>
                                </div>
                              </div>

                              {/* Vulnerability Breakdown */}
                              <div className="p-6 space-y-6">
                                <div>
                                  <h5 className="text-lg font-semibold text-red-400 mb-4 flex items-center gap-2">
                                    💥 Vulnerability Breakdown
                                  </h5>

                                  <div className="space-y-4">
                                    <div className="p-4 bg-slate-800/50 rounded-lg border border-slate-700/50">
                                      <p className="text-xs text-slate-500 font-mono uppercase mb-2">Flaw</p>
                                      <p className="text-sm text-slate-300">{breakdown.flaw}</p>
                                    </div>

                                    <div className="p-4 bg-slate-800/50 rounded-lg border border-slate-700/50">
                                      <p className="text-xs text-slate-500 font-mono uppercase mb-2">Mechanism</p>
                                      <p className="text-sm text-slate-300">{breakdown.mechanism}</p>
                                    </div>

                                    <div className="p-4 bg-slate-800/50 rounded-lg border border-slate-700/50">
                                      <p className="text-xs text-slate-500 font-mono uppercase mb-2">Outcome</p>
                                      <p className="text-sm text-slate-300">{breakdown.outcome}</p>
                                    </div>

                                    <div className="p-4 bg-gradient-to-r from-red-500/10 to-orange-500/10 border border-red-500/30 rounded-lg">
                                      <p className="text-xs text-slate-500 font-mono uppercase mb-2">Impact</p>
                                      <p className="text-sm text-red-300 font-medium">{breakdown.impact}</p>
                                    </div>

                                    {/* Technical Details */}
                                    <div className="grid grid-cols-2 gap-3">
                                      <div className="p-3 bg-slate-800/50 rounded border border-slate-700/50">
                                        <p className="text-xs text-slate-500 mb-1">Attack Vector</p>
                                        <p className="text-sm text-white font-mono">{breakdown.attackVector}</p>
                                      </div>
                                      <div className="p-3 bg-slate-800/50 rounded border border-slate-700/50">
                                        <p className="text-xs text-slate-500 mb-1">Attack Complexity</p>
                                        <p className="text-sm text-white font-mono">{breakdown.attackComplexity}</p>
                                      </div>
                                      <div className="p-3 bg-slate-800/50 rounded border border-slate-700/50">
                                        <p className="text-xs text-slate-500 mb-1">Privileges Required</p>
                                        <p className="text-sm text-white font-mono">{breakdown.privilegesRequired}</p>
                                      </div>
                                      <div className="p-3 bg-slate-800/50 rounded border border-slate-700/50">
                                        <p className="text-xs text-slate-500 mb-1">User Interaction</p>
                                        <p className="text-sm text-white font-mono">{breakdown.userInteraction}</p>
                                      </div>
                                    </div>

                                    {/* Affected Versions */}
                                    <div className="p-4 bg-slate-800/50 rounded-lg border border-slate-700/50">
                                      <p className="text-xs text-slate-500 font-mono uppercase mb-2">Affected Versions</p>
                                      <ul className="space-y-1">
                                        {breakdown.affectedVersions.map((version, i) => (
                                          <li key={i} className="text-sm text-slate-300 font-mono">• {version}</li>
                                        ))}
                                      </ul>
                                    </div>
                                  </div>
                                </div>

                                {/* Mitigation & Action */}
                                <div>
                                  <h5 className="text-lg font-semibold text-green-400 mb-4 flex items-center gap-2">
                                    🛡️ Mitigation & Action
                                  </h5>

                                  <div className="space-y-4">
                                    {/* Emergency Patching */}
                                    <div className="p-4 bg-gradient-to-r from-red-500/10 to-orange-500/10 border border-red-500/30 rounded-lg">
                                      <div className="flex items-center gap-2 mb-2">
                                        <span className="px-2 py-1 bg-red-500/20 text-red-400 border border-red-500/30 rounded text-xs font-mono">
                                          {cveMitigation.emergencyPatching.priority.toUpperCase()}
                                        </span>
                                        <h6 className="font-semibold text-white">{cveMitigation.emergencyPatching.title}</h6>
                                      </div>
                                      <p className="text-sm text-slate-300 mb-3">{cveMitigation.emergencyPatching.description}</p>
                                      <div className="space-y-2">
                                        <p className="text-xs text-slate-500 font-mono uppercase">Required Patches:</p>
                                        {cveMitigation.emergencyPatching.patches.map((patch, i) => (
                                          <div key={i} className="p-2 bg-slate-900 rounded border border-slate-700">
                                            <p className="text-xs font-mono text-cyan-400">{patch}</p>
                                          </div>
                                        ))}
                                      </div>
                                      <p className="text-xs text-orange-400 font-semibold mt-3">
                                        ⏰ Timeframe: {cveMitigation.emergencyPatching.timeframe}
                                      </p>
                                    </div>

                                    {/* Immediate Action */}
                                    <div className="p-4 bg-slate-800/50 rounded-lg border border-orange-500/30">
                                      <div className="flex items-center gap-2 mb-2">
                                        <span className="px-2 py-1 bg-orange-500/20 text-orange-400 border border-orange-500/30 rounded text-xs font-mono">
                                          {cveMitigation.immediateAction.priority.toUpperCase()}
                                        </span>
                                        <h6 className="font-semibold text-white">{cveMitigation.immediateAction.title}</h6>
                                      </div>
                                      <p className="text-sm text-slate-300 mb-3">{cveMitigation.immediateAction.description}</p>
                                      <ul className="space-y-1">
                                        {cveMitigation.immediateAction.actions.map((action, i) => (
                                          <li key={i} className="text-sm text-slate-300">• {action}</li>
                                        ))}
                                      </ul>
                                      <p className="text-xs text-orange-400 font-semibold mt-3">
                                        ⏰ Timeframe: {cveMitigation.immediateAction.timeframe}
                                      </p>
                                    </div>

                                    {/* Post-Patch */}
                                    <div className="p-4 bg-slate-800/50 rounded-lg border border-slate-700/50">
                                      <div className="flex items-center gap-2 mb-2">
                                        <span className="px-2 py-1 bg-blue-500/20 text-blue-400 border border-blue-500/30 rounded text-xs font-mono">
                                          {cveMitigation.postPatch.priority.toUpperCase()}
                                        </span>
                                        <h6 className="font-semibold text-white">{cveMitigation.postPatch.title}</h6>
                                      </div>
                                      <p className="text-sm text-slate-300 mb-3">{cveMitigation.postPatch.description}</p>
                                      <ul className="space-y-1">
                                        {cveMitigation.postPatch.actions.map((action, i) => (
                                          <li key={i} className="text-sm text-slate-300">• {action}</li>
                                        ))}
                                      </ul>
                                      <p className="text-xs text-blue-400 font-semibold mt-3">
                                        ⏰ Timeframe: {cveMitigation.postPatch.timeframe}
                                      </p>
                                    </div>

                                    {/* Detection & Monitoring */}
                                    <div className="p-4 bg-gradient-to-r from-purple-500/10 to-pink-500/10 border border-purple-500/30 rounded-lg">
                                      <div className="flex items-center gap-2 mb-2">
                                        <span className="px-2 py-1 bg-purple-500/20 text-purple-400 border border-purple-500/30 rounded text-xs font-mono">
                                          {cveMitigation.detection.priority.toUpperCase()}
                                        </span>
                                        <h6 className="font-semibold text-white">{cveMitigation.detection.title}</h6>
                                      </div>
                                      <p className="text-sm text-slate-300 mb-3">{cveMitigation.detection.description}</p>
                                      <div className="space-y-1">
                                        <p className="text-xs text-slate-500 font-mono uppercase mb-2">Indicators of Compromise (IOCs):</p>
                                        {cveMitigation.detection.iocs.map((ioc, i) => (
                                          <div key={i} className="p-2 bg-slate-900 rounded border border-slate-700">
                                            <p className="text-xs font-mono text-purple-400">• {ioc}</p>
                                          </div>
                                        ))}
                                      </div>
                                    </div>
                                  </div>
                                </div>

                                {/* External Links */}
                                <div className="p-4 bg-slate-800/50 rounded-lg border border-slate-700/50">
                                  <p className="text-xs text-slate-500 font-mono uppercase mb-3">External Resources</p>
                                  <div className="grid grid-cols-2 gap-2">
                                    <a href={links.nvd} target="_blank" rel="noopener noreferrer" className="text-xs text-cyan-400 hover:text-cyan-300">
                                      📚 NVD Database →
                                    </a>
                                    <a href={links.cisa} target="_blank" rel="noopener noreferrer" className="text-xs text-cyan-400 hover:text-cyan-300">
                                      🏛️ CISA KEV Catalog →
                                    </a>
                                    <a href={links.github} target="_blank" rel="noopener noreferrer" className="text-xs text-cyan-400 hover:text-cyan-300">
                                      💻 GitHub Advisories →
                                    </a>
                                    <a href={links.exploitdb} target="_blank" rel="noopener noreferrer" className="text-xs text-cyan-400 hover:text-cyan-300">
                                      💣 ExploitDB →
                                    </a>
                                    {cve.notes && (
                                      <a href={cve.notes} target="_blank" rel="noopener noreferrer" className="text-xs text-cyan-400 hover:text-cyan-300 col-span-2">
                                        🔗 Vendor Advisory →
                                      </a>
                                    )}
                                  </div>
                                </div>

                                {/* CISA Notes */}
                                {cve.requiredAction && (
                                  <div className="p-4 bg-gradient-to-r from-red-500/10 to-rose-500/10 border border-red-500/30 rounded-lg">
                                    <p className="text-xs text-red-400 font-mono uppercase mb-2">CISA Required Action</p>
                                    <p className="text-sm text-slate-300">{cve.requiredAction}</p>
                                  </div>
                                )}
                              </div>
                            </div>
                          );
                        })}
                      </>
                    )}
                  </div>
                )}

                {threatDetailTab === 'mitre' && (
                  <div className="space-y-6">
                    <div className="p-4 bg-gradient-to-r from-red-500/10 to-orange-500/10 border border-red-500/30 rounded-lg">
                      <h3 className="text-lg font-semibold text-red-400 mb-2">🎯 MITRE ATT&CK Techniques</h3>
                      <p className="text-sm text-slate-400">
                        This threat maps to the following MITRE ATT&CK techniques based on its characteristics and behavior patterns.
                      </p>
                    </div>

                    <div className="grid gap-4">
                      {mitreData.map((technique, idx) => {
                        const tactic = MITRE_TACTICS[technique.tactic];
                        return (
                          <div key={idx} className="p-4 bg-slate-800/50 rounded-lg border border-slate-700/50 hover:border-cyan-500/50 transition-all">
                            <div className="flex items-start justify-between mb-2">
                              <div>
                                <div className="flex items-center gap-2 mb-1">
                                  <span className="px-2 py-0.5 bg-red-500/20 text-red-400 border border-red-500/30 rounded text-xs font-mono">
                                    {technique.id}
                                  </span>
                                  {tactic && (
                                    <span className="px-2 py-0.5 bg-orange-500/20 text-orange-400 border border-orange-500/30 rounded text-xs font-mono">
                                      {tactic.id}
                                    </span>
                                  )}
                                </div>
                                <h4 className="font-semibold text-white">{technique.name}</h4>
                                {tactic && <p className="text-xs text-slate-500 mt-1">Tactic: {tactic.name}</p>}
                              </div>
                              <a
                                href={getMitreTechniqueUrl(technique.id)}
                                target="_blank"
                                rel="noopener noreferrer"
                                className="text-cyan-400 hover:text-cyan-300 text-sm"
                              >
                                View Details →
                              </a>
                            </div>
                            <p className="text-sm text-slate-400">{technique.description}</p>
                            {tactic && (
                              <p className="text-xs text-slate-500 mt-2 italic">{tactic.description}</p>
                            )}
                          </div>
                        );
                      })}
                    </div>

                    <div className="p-4 bg-slate-800/50 rounded-lg border border-slate-700/50">
                      <p className="text-xs text-slate-500 mb-2">Learn more about MITRE ATT&CK:</p>
                      <a
                        href="https://attack.mitre.org/"
                        target="_blank"
                        rel="noopener noreferrer"
                        className="text-cyan-400 hover:text-cyan-300 text-sm"
                      >
                        https://attack.mitre.org/ →
                      </a>
                    </div>
                  </div>
                )}

                {threatDetailTab === 'mitigations' && (
                  <div className="space-y-6">
                    <div className="p-4 bg-gradient-to-r from-green-500/10 to-emerald-500/10 border border-green-500/30 rounded-lg">
                      <h3 className="text-lg font-semibold text-green-400 mb-2">🛡️ Mitigation Recommendations</h3>
                      <p className="text-sm text-slate-400">
                        Implement these security controls to protect against this threat.
                      </p>
                    </div>

                    <div className="grid gap-4">
                      {mitigations.map((mitigation, idx) => (
                        <div key={idx} className="p-4 bg-slate-800/50 rounded-lg border border-slate-700/50">
                          <div className="flex items-start justify-between mb-3">
                            <div className="flex items-center gap-3">
                              <span className={`px-2 py-1 rounded text-xs font-mono ${
                                mitigation.priority === 'critical' ? 'bg-red-500/20 text-red-400 border border-red-500/30' :
                                mitigation.priority === 'high' ? 'bg-orange-500/20 text-orange-400 border border-orange-500/30' :
                                'bg-yellow-500/20 text-yellow-400 border border-yellow-500/30'
                              }`}>
                                {mitigation.priority.toUpperCase()}
                              </span>
                              <span className="text-xs text-slate-500 font-mono">{mitigation.category}</span>
                            </div>
                          </div>
                          <h4 className="font-semibold text-white mb-2">{mitigation.title}</h4>
                          <p className="text-sm text-slate-400 mb-3">{mitigation.description}</p>
                          <div>
                            <p className="text-xs text-slate-500 font-mono uppercase mb-2">Recommended Tools:</p>
                            <div className="flex flex-wrap gap-2">
                              {mitigation.tools.map((tool, i) => (
                                <span key={i} className="px-2 py-1 bg-blue-500/20 text-blue-400 border border-blue-500/30 rounded text-xs">
                                  {tool}
                                </span>
                              ))}
                            </div>
                          </div>
                        </div>
                      ))}
                    </div>
                  </div>
                )}

                {threatDetailTab === 'remediation' && (
                  <div className="space-y-6">
                    <div className="p-4 bg-gradient-to-r from-blue-500/10 to-purple-500/10 border border-blue-500/30 rounded-lg">
                      <h3 className="text-lg font-semibold text-blue-400 mb-2">🔧 Incident Response Playbook</h3>
                      <p className="text-sm text-slate-400 mb-3">
                        Follow this step-by-step remediation guide to respond to this threat.
                      </p>
                      <div className="flex gap-4 text-xs">
                        <div><span className="text-slate-500">Threat:</span> <span className="text-white font-medium">{remediation.threat}</span></div>
                        <div><span className="text-slate-500">Estimated Time:</span> <span className="text-cyan-400 font-medium">{remediation.estimatedTotalTime}</span></div>
                      </div>
                    </div>

                    <div className="space-y-4">
                      {remediation.steps.map((step, idx) => {
                        const isNewPhase = idx === 0 || remediation.steps[idx - 1].phase !== step.phase;
                        return (
                          <div key={idx}>
                            {isNewPhase && (
                              <div className="flex items-center gap-3 mb-3">
                                <div className="h-px flex-1 bg-gradient-to-r from-transparent via-cyan-500/50 to-transparent" />
                                <h4 className="text-sm font-mono text-cyan-400 uppercase">{step.phase}</h4>
                                <div className="h-px flex-1 bg-gradient-to-r from-cyan-500/50 via-transparent to-transparent" />
                              </div>
                            )}
                            <div className="p-4 bg-slate-800/50 rounded-lg border border-slate-700/50">
                              <div className="flex items-start gap-3 mb-3">
                                <div className="flex-shrink-0 w-8 h-8 bg-cyan-500/20 border border-cyan-500/30 rounded-full flex items-center justify-center">
                                  <span className="text-cyan-400 font-mono text-sm">{step.order}</span>
                                </div>
                                <div className="flex-1">
                                  <h5 className="font-semibold text-white mb-1">{step.title}</h5>
                                  <p className="text-sm text-slate-400 mb-3">{step.description}</p>
                                  <div className="space-y-2">
                                    {step.commands.map((cmd, i) => (
                                      <div key={i} className="p-2 bg-slate-900 rounded border border-slate-700">
                                        <p className="text-xs font-mono text-cyan-400">{cmd}</p>
                                      </div>
                                    ))}
                                  </div>
                                  <div className="flex gap-4 mt-3 text-xs">
                                    <div><span className="text-slate-500">Time:</span> <span className="text-slate-300">{step.estimatedTime}</span></div>
                                    <div><span className="text-slate-500">Role:</span> <span className="text-slate-300">{step.role}</span></div>
                                  </div>
                                </div>
                              </div>
                            </div>
                          </div>
                        );
                      })}
                    </div>

                    <div className="p-4 bg-slate-800/50 rounded-lg border border-slate-700/50">
                      <p className="text-xs text-slate-500 font-mono uppercase mb-2">References</p>
                      <ul className="space-y-1">
                        {remediation.references.map((ref, i) => (
                          <li key={i} className="text-sm text-slate-400">• {ref}</li>
                        ))}
                      </ul>
                    </div>
                  </div>
                )}
              </div>
            </div>
          </div>
        );
      })()}

      {selectedCVE && (() => {
        const breakdown = generateVulnerabilityBreakdown({ cveId: selectedCVE.cveId });
        const cveMitigation = generateCVEMitigation({ cveId: selectedCVE.cveId });
        const links = getCVELinks(selectedCVE.cveId);
        const cveMitreData = mapCVEToMitre(selectedCVE);

        const today = new Date();
        const dueDate = new Date(selectedCVE.dueDate);
        const daysUntilDue = Math.ceil((dueDate - today) / (1000 * 60 * 60 * 24));
        const isOverdue = daysUntilDue < 0;
        const isUrgent = daysUntilDue >= 0 && daysUntilDue <= 7;

        return (
          <div className="fixed inset-0 bg-slate-950/80 backdrop-blur-sm z-50 flex items-center justify-center p-6 overflow-y-auto">
            <div className="bg-slate-900 border border-slate-700 rounded-xl max-w-6xl w-full my-8">
              <div className="sticky top-0 bg-slate-900 border-b border-slate-700 p-6 flex items-start justify-between z-10">
                <div className="flex-1">
                  <div className="flex items-center gap-3 mb-3 flex-wrap">
                    <span className="px-3 py-1 bg-red-500/30 text-red-300 border-2 border-red-500/50 rounded-full text-sm font-mono font-bold animate-pulse">
                      🚨 CISA KEV
                    </span>
                    <h2 className="text-2xl font-bold font-mono text-cyan-400">{selectedCVE.cveId}</h2>
                    {selectedCVE.knownRansomwareCampaignUse === 'Known' && (
                      <span className="px-3 py-1 bg-purple-500/20 text-purple-400 border border-purple-500/30 rounded-full text-xs font-mono animate-pulse">
                        🔒 RANSOMWARE
                      </span>
                    )}
                    {isOverdue ? (
                      <span className="px-3 py-1 bg-red-500/20 text-red-400 border border-red-500/30 rounded-full text-xs font-mono animate-pulse">
                        ⚠️ OVERDUE
                      </span>
                    ) : isUrgent && (
                      <span className="px-3 py-1 bg-orange-500/20 text-orange-400 border border-orange-500/30 rounded-full text-xs font-mono animate-pulse">
                        🚨 URGENT
                      </span>
                    )}
                  </div>
                  <h3 className="text-lg font-semibold text-white mb-2">{selectedCVE.vulnerabilityName}</h3>
                  <p className="text-sm text-slate-400">{selectedCVE.vendorProject} - {selectedCVE.product}</p>
                </div>
                <button onClick={() => { setSelectedCVE(null); setCveDetailTab('overview'); }} className="p-2 hover:bg-slate-800 rounded-lg text-slate-400 hover:text-white text-xl">
                  ✕
                </button>
              </div>

              <div className="border-b border-slate-700">
                <nav className="flex px-6 overflow-x-auto">
                  {[
                    { id: 'overview', label: 'Overview', icon: '📊' },
                    { id: 'mitre', label: 'MITRE ATT&CK', icon: '🎯', badge: cveMitreData.length },
                    { id: 'breakdown', label: 'Vulnerability', icon: '💥' },
                    { id: 'mitigation', label: 'Mitigation', icon: '🛡️' }
                  ].map(tab => (
                    <button
                      key={tab.id}
                      onClick={() => setCveDetailTab(tab.id)}
                      className={`px-4 py-3 text-sm font-medium border-b-2 transition-colors flex items-center gap-2 ${
                        cveDetailTab === tab.id
                          ? 'border-cyan-500 text-cyan-400'
                          : 'border-transparent text-slate-400 hover:text-white hover:border-slate-600'
                      }`}
                    >
                      <span>{tab.icon}</span>
                      <span>{tab.label}</span>
                      {tab.badge && (
                        <span className="px-1.5 py-0.5 bg-cyan-500 text-white text-xs rounded-full font-mono">
                          {tab.badge}
                        </span>
                      )}
                    </button>
                  ))}
                </nav>
              </div>

              <div className="p-6 max-h-[60vh] overflow-y-auto space-y-6">
                {/* Overview Tab */}
                {cveDetailTab === 'overview' && (
                  <>
                    {/* Quick Info */}
                    <div className="grid grid-cols-3 gap-4">
                      <div className="p-4 bg-slate-800/50 rounded-lg border border-slate-700/50">
                        <p className="text-xs text-slate-500 font-mono uppercase mb-1">Added to KEV</p>
                        <p className="text-white font-semibold">{selectedCVE.dateAdded}</p>
                      </div>
                      <div className="p-4 bg-slate-800/50 rounded-lg border border-slate-700/50">
                        <p className="text-xs text-slate-500 font-mono uppercase mb-1">Due Date</p>
                        <p className={`font-semibold ${isOverdue ? 'text-red-400' : isUrgent ? 'text-orange-400' : 'text-white'}`}>
                          {selectedCVE.dueDate}
                        </p>
                        <p className="text-xs text-slate-500 mt-1">
                          {isOverdue ? `${Math.abs(daysUntilDue)} days overdue` : `${daysUntilDue} days remaining`}
                        </p>
                      </div>
                      <div className="p-4 bg-slate-800/50 rounded-lg border border-slate-700/50">
                        <p className="text-xs text-slate-500 font-mono uppercase mb-1">Ransomware Use</p>
                        <p className={`font-semibold ${selectedCVE.knownRansomwareCampaignUse === 'Known' ? 'text-purple-400' : 'text-slate-400'}`}>
                          {selectedCVE.knownRansomwareCampaignUse || 'Unknown'}
                        </p>
                      </div>
                    </div>

                    {/* Description */}
                    <div className="p-4 bg-slate-800/50 rounded-lg border border-slate-700/50">
                      <p className="text-xs text-slate-500 font-mono uppercase mb-2">Description</p>
                      <p className="text-slate-300 text-sm leading-relaxed">{selectedCVE.shortDescription}</p>
                    </div>

                    {/* CISA Required Action */}
                    <div className="p-4 bg-gradient-to-r from-red-500/10 to-rose-500/10 border border-red-500/30 rounded-lg">
                      <p className="text-xs text-red-400 font-mono uppercase mb-2">⚠️ CISA Required Action</p>
                      <p className="text-slate-300 text-sm leading-relaxed">{selectedCVE.requiredAction}</p>
                    </div>

                    {/* External Links */}
                    <div className="p-4 bg-slate-800/50 rounded-lg border border-slate-700/50">
                      <p className="text-xs text-slate-500 font-mono uppercase mb-3">External Resources</p>
                      <div className="grid grid-cols-2 gap-2">
                        <a href={links.nvd} target="_blank" rel="noopener noreferrer" className="text-xs text-cyan-400 hover:text-cyan-300">
                          📚 NVD Database →
                        </a>
                        <a href={links.cisa} target="_blank" rel="noopener noreferrer" className="text-xs text-cyan-400 hover:text-cyan-300">
                          🏛️ CISA KEV Catalog →
                        </a>
                        <a href={links.github} target="_blank" rel="noopener noreferrer" className="text-xs text-cyan-400 hover:text-cyan-300">
                          💻 GitHub Advisories →
                        </a>
                        <a href={links.exploitdb} target="_blank" rel="noopener noreferrer" className="text-xs text-cyan-400 hover:text-cyan-300">
                          💣 ExploitDB →
                        </a>
                        {selectedCVE.notes && (
                          <a href={selectedCVE.notes} target="_blank" rel="noopener noreferrer" className="text-xs text-cyan-400 hover:text-cyan-300 col-span-2">
                            🔗 Vendor Advisory →
                          </a>
                        )}
                      </div>
                    </div>

                    {/* Actions */}
                    <div className="flex gap-3 pt-4 border-t border-slate-700">
                      <button
                        onClick={() => navigator.clipboard.writeText(selectedCVE.cveId)}
                        className="flex-1 px-4 py-2 bg-cyan-500/20 text-cyan-400 border border-cyan-500/30 rounded-lg font-medium hover:bg-cyan-500/30"
                      >
                        📋 Copy CVE ID
                      </button>
                      <button
                        onClick={() => window.open(links.nvd, '_blank')}
                        className="flex-1 px-4 py-2 bg-slate-700 text-white rounded-lg font-medium hover:bg-slate-600"
                      >
                        🔍 View in NVD
                      </button>
                    </div>
                  </>
                )}

                {/* MITRE ATT&CK Tab */}
                {cveDetailTab === 'mitre' && (
                  <div className="space-y-4">
                    {cveMitreData.length > 0 ? (
                      <>
                        <div className="p-4 bg-gradient-to-r from-cyan-500/10 to-blue-500/10 border border-cyan-500/30 rounded-lg">
                          <p className="text-sm text-slate-300">
                            This vulnerability maps to <span className="text-cyan-400 font-semibold">{cveMitreData.length} MITRE ATT&CK technique{cveMitreData.length !== 1 ? 's' : ''}</span> based on its characteristics and exploitation patterns.
                          </p>
                        </div>

                        {cveMitreData.map((technique) => {
                          const tactic = MITRE_TACTICS[technique.tactic];
                          return (
                            <div key={technique.id} className="p-4 bg-slate-800/50 border border-slate-700/50 rounded-lg hover:border-cyan-500/50 transition-colors">
                              <div className="flex items-start justify-between mb-3">
                                <div>
                                  <span className="inline-block px-2 py-1 bg-cyan-500/20 text-cyan-400 border border-cyan-500/30 rounded text-xs font-mono font-semibold mb-2">
                                    {technique.id}
                                  </span>
                                  <h4 className="text-lg font-semibold text-white">{technique.name}</h4>
                                </div>
                              </div>
                              <p className="text-sm text-slate-400 mb-3">{technique.description}</p>
                              <div className="flex items-center gap-2">
                                <span className="text-xs text-slate-500 font-mono uppercase">Tactic:</span>
                                <span className="px-2 py-0.5 bg-purple-500/20 text-purple-400 border border-purple-500/30 rounded text-xs font-mono">
                                  {tactic.id} - {tactic.name}
                                </span>
                              </div>
                              <a
                                href={`https://attack.mitre.org/techniques/${technique.id}/`}
                                target="_blank"
                                rel="noopener noreferrer"
                                className="inline-block mt-3 text-xs text-cyan-400 hover:text-cyan-300"
                              >
                                📖 View on MITRE ATT&CK →
                              </a>
                            </div>
                          );
                        })}

                        <div className="p-4 bg-slate-800/50 rounded-lg border border-slate-700/50">
                          <p className="text-xs text-slate-500 font-mono uppercase mb-2">MITRE ATT&CK Resources</p>
                          <div className="space-y-2">
                            <a
                              href="https://mitre-attack.github.io/attack-navigator/"
                              target="_blank"
                              rel="noopener noreferrer"
                              className="block text-sm text-cyan-400 hover:text-cyan-300"
                            >
                              🗺️ MITRE ATT&CK Navigator →
                            </a>
                            <a
                              href="https://attack.mitre.org/"
                              target="_blank"
                              rel="noopener noreferrer"
                              className="block text-sm text-cyan-400 hover:text-cyan-300"
                            >
                              📚 MITRE ATT&CK Framework →
                            </a>
                          </div>
                        </div>
                      </>
                    ) : (
                      <div className="p-8 text-center">
                        <p className="text-slate-400">No MITRE ATT&CK techniques mapped for this CVE.</p>
                      </div>
                    )}
                  </div>
                )}

                {/* Vulnerability Breakdown Tab */}
                {cveDetailTab === 'breakdown' && (
                  <div className="space-y-4">
                    <div className="p-4 bg-slate-800/50 rounded-lg border border-slate-700/50">
                      <p className="text-xs text-slate-500 font-mono uppercase mb-2">🔍 Flaw</p>
                      <p className="text-sm text-slate-300 leading-relaxed">{breakdown.flaw}</p>
                    </div>
                    <div className="p-4 bg-slate-800/50 rounded-lg border border-slate-700/50">
                      <p className="text-xs text-slate-500 font-mono uppercase mb-2">⚙️ Mechanism</p>
                      <p className="text-sm text-slate-300 leading-relaxed">{breakdown.mechanism}</p>
                    </div>
                    <div className="p-4 bg-slate-800/50 rounded-lg border border-slate-700/50">
                      <p className="text-xs text-slate-500 font-mono uppercase mb-2">💥 Outcome</p>
                      <p className="text-sm text-slate-300 leading-relaxed">{breakdown.outcome}</p>
                    </div>
                    <div className="p-4 bg-gradient-to-r from-red-500/10 to-orange-500/10 border border-red-500/30 rounded-lg">
                      <p className="text-xs text-red-400 font-mono uppercase mb-2">⚠️ Impact</p>
                      <p className="text-sm text-red-300 font-medium leading-relaxed">{breakdown.impact}</p>
                    </div>
                  </div>
                )}

                {/* Mitigation Tab */}
                {cveDetailTab === 'mitigation' && (
                  <div className="space-y-4">
                    {/* Emergency Patching */}
                    <div className="p-4 bg-gradient-to-r from-red-500/10 to-orange-500/10 border border-red-500/30 rounded-lg">
                      <div className="flex items-center gap-2 mb-3">
                        <span className="px-2 py-1 bg-red-500/30 text-red-300 border border-red-500/50 rounded text-xs font-mono font-bold">
                          {cveMitigation.emergencyPatching.priority.toUpperCase()}
                        </span>
                        <h4 className="text-lg font-semibold text-red-300">{cveMitigation.emergencyPatching.title}</h4>
                      </div>
                      <p className="text-sm text-slate-300 leading-relaxed mb-3">{cveMitigation.emergencyPatching.description}</p>
                      <div className="space-y-2">
                        {cveMitigation.emergencyPatching.steps.map((step, idx) => (
                          <div key={idx} className="flex items-start gap-2">
                            <span className="text-red-400 font-bold">•</span>
                            <p className="text-sm text-slate-300">{step}</p>
                          </div>
                        ))}
                      </div>
                    </div>

                    {/* Immediate Action */}
                    <div className="p-4 bg-gradient-to-r from-orange-500/10 to-yellow-500/10 border border-orange-500/30 rounded-lg">
                      <div className="flex items-center gap-2 mb-3">
                        <span className="px-2 py-1 bg-orange-500/30 text-orange-300 border border-orange-500/50 rounded text-xs font-mono font-bold">
                          {cveMitigation.immediateAction.priority.toUpperCase()}
                        </span>
                        <h4 className="text-lg font-semibold text-orange-300">{cveMitigation.immediateAction.title}</h4>
                      </div>
                      <p className="text-sm text-slate-300 leading-relaxed mb-3">{cveMitigation.immediateAction.description}</p>
                      <div className="space-y-2">
                        {cveMitigation.immediateAction.steps.map((step, idx) => (
                          <div key={idx} className="flex items-start gap-2">
                            <span className="text-orange-400 font-bold">•</span>
                            <p className="text-sm text-slate-300">{step}</p>
                          </div>
                        ))}
                      </div>
                    </div>

                    {/* Post-Patch Actions */}
                    <div className="p-4 bg-slate-800/50 border border-slate-700/50 rounded-lg">
                      <div className="flex items-center gap-2 mb-3">
                        <span className="px-2 py-1 bg-green-500/30 text-green-300 border border-green-500/50 rounded text-xs font-mono font-bold">
                          {cveMitigation.postPatch.priority.toUpperCase()}
                        </span>
                        <h4 className="text-lg font-semibold text-green-300">{cveMitigation.postPatch.title}</h4>
                      </div>
                      <p className="text-sm text-slate-300 leading-relaxed mb-3">{cveMitigation.postPatch.description}</p>
                      <div className="space-y-2">
                        {cveMitigation.postPatch.steps.map((step, idx) => (
                          <div key={idx} className="flex items-start gap-2">
                            <span className="text-green-400 font-bold">•</span>
                            <p className="text-sm text-slate-300">{step}</p>
                          </div>
                        ))}
                      </div>
                    </div>

                    {/* Detection Methods */}
                    <div className="p-4 bg-slate-800/50 border border-cyan-500/30 rounded-lg">
                      <div className="flex items-center gap-2 mb-3">
                        <span className="px-2 py-1 bg-cyan-500/30 text-cyan-300 border border-cyan-500/50 rounded text-xs font-mono font-bold">
                          INFO
                        </span>
                        <h4 className="text-lg font-semibold text-cyan-300">{cveMitigation.detection.title}</h4>
                      </div>
                      <p className="text-sm text-slate-300 leading-relaxed mb-3">{cveMitigation.detection.description}</p>
                      <div className="space-y-2">
                        {cveMitigation.detection.methods.map((method, idx) => (
                          <div key={idx} className="flex items-start gap-2">
                            <span className="text-cyan-400 font-bold">•</span>
                            <p className="text-sm text-slate-300">{method}</p>
                          </div>
                        ))}
                      </div>
                    </div>
                  </div>
                )}
              </div>
            </div>
          </div>
        );
      })()}

      <style>{`
        @import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;500;600&family=Inter:wght@400;500;600;700&display=swap');
        body { font-family: 'Inter', sans-serif; }
        .font-mono { font-family: 'JetBrains Mono', monospace; }
      `}</style>
    </div>
  );
}
