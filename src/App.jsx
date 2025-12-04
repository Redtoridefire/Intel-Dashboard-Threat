import React, { useState, useEffect, useCallback } from 'react';
import { PieChart, Pie, Cell, Tooltip, ResponsiveContainer } from 'recharts';

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
  const [selectedThreat, setSelectedThreat] = useState(null);
  const [searchQuery, setSearchQuery] = useState('');
  const [filterSeverity, setFilterSeverity] = useState('all');
  const [currentTime, setCurrentTime] = useState(new Date());
  const [loading, setLoading] = useState({ threats: true, feeds: true });
  const [errors, setErrors] = useState({});
  const [unifiedSearchQuery, setUnifiedSearchQuery] = useState('');
  const [unifiedSearchResults, setUnifiedSearchResults] = useState(null);
  const [searchLoading, setSearchLoading] = useState(false);

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
      setErrors(prev => ({ ...prev, threats: null }));
    } catch (error) {
      setErrors(prev => ({ ...prev, threats: error.message }));
    } finally {
      setLoading(prev => ({ ...prev, threats: false }));
    }
  }, []);

  useEffect(() => { fetchFeeds(); fetchThreats(); }, [fetchFeeds, fetchThreats]);
  useEffect(() => { const interval = setInterval(fetchThreats, 60000); return () => clearInterval(interval); }, [fetchThreats]);

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
    return matchesSearch && (filterSeverity === 'all' || t.severity === filterSeverity);
  });

  const stats = {
    total: threats.length,
    critical: threats.filter(t => t.severity === 'critical').length,
    high: threats.filter(t => t.severity === 'high').length,
    connectedFeeds: feeds.filter(f => f.status === 'connected').length
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
                {['overview', 'threats', 'search', 'feeds'].map(tab => (
                  <button key={tab} onClick={() => setActiveTab(tab)} className={`px-4 py-2 text-sm font-medium rounded-lg transition-all ${activeTab === tab ? 'bg-cyan-500/20 text-cyan-400 border border-cyan-500/30' : 'text-slate-400 hover:text-white hover:bg-slate-800'}`}>
                    {tab.charAt(0).toUpperCase() + tab.slice(1)}
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
              <div className="flex flex-wrap items-center gap-4">
                <div className="flex-1 min-w-[300px]"><input type="text" placeholder="Search threats..." value={searchQuery} onChange={(e) => setSearchQuery(e.target.value)} className="w-full px-4 py-2 bg-slate-800 border border-slate-700 rounded-lg text-sm font-mono focus:outline-none focus:border-cyan-500" /></div>
                <div className="flex gap-2">{['all', 'critical', 'high', 'medium', 'low'].map(sev => <button key={sev} onClick={() => setFilterSeverity(sev)} className={`px-3 py-2 text-xs font-mono rounded-lg ${filterSeverity === sev ? 'bg-cyan-500/20 text-cyan-400 border border-cyan-500/30' : 'bg-slate-800 text-slate-400 border border-slate-700'}`}>{sev.toUpperCase()}</button>)}</div>
                <button onClick={fetchThreats} className="px-4 py-2 bg-cyan-500/20 text-cyan-400 border border-cyan-500/30 rounded-lg text-sm font-mono">↻ Refresh</button>
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

      {selectedThreat && (
        <div className="fixed inset-0 bg-slate-950/80 backdrop-blur-sm z-50 flex items-center justify-center p-6">
          <div className="bg-slate-900 border border-slate-700 rounded-xl max-w-3xl w-full max-h-[90vh] overflow-y-auto">
            <div className="sticky top-0 bg-slate-900 border-b border-slate-700 p-6 flex items-start justify-between">
              <div><div className="flex items-center gap-3 mb-2"><SeverityBadge severity={selectedThreat.severity} /><span className="text-xs text-slate-500 font-mono">{selectedThreat.source}</span></div><h2 className="text-xl font-bold">{selectedThreat.name}</h2><p className="text-sm text-slate-400 mt-1">{selectedThreat.type}</p></div>
              <button onClick={() => setSelectedThreat(null)} className="p-2 hover:bg-slate-800 rounded-lg">✕</button>
            </div>
            <div className="p-6 space-y-6">
              {selectedThreat.indicator && <div className="p-4 bg-slate-800/50 rounded-lg"><p className="text-xs text-slate-500 font-mono uppercase mb-1">Indicator</p><p className="font-mono text-cyan-400 break-all">{selectedThreat.indicator}</p></div>}
              {selectedThreat.tags?.length > 0 && <div><h3 className="text-sm font-mono text-slate-500 uppercase mb-3">Tags</h3><div className="flex flex-wrap gap-2">{selectedThreat.tags.map((tag, i) => <span key={i} className="px-3 py-1 bg-purple-500/20 text-purple-400 border border-purple-500/30 rounded-full text-sm">{tag}</span>)}</div></div>}
              <div className="flex gap-3 pt-4 border-t border-slate-700">
                <button onClick={() => navigator.clipboard.writeText(selectedThreat.indicator || selectedThreat.id)} className="flex-1 px-4 py-2 bg-cyan-500/20 text-cyan-400 border border-cyan-500/30 rounded-lg font-medium hover:bg-cyan-500/30">Copy Indicator</button>
                <button onClick={() => { setUnifiedSearchQuery(selectedThreat.indicator); setActiveTab('search'); setSelectedThreat(null); }} className="flex-1 px-4 py-2 bg-slate-700 text-white rounded-lg font-medium hover:bg-slate-600">Deep Search</button>
              </div>
            </div>
          </div>
        </div>
      )}

      <style>{`
        @import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;500;600&family=Inter:wght@400;500;600;700&display=swap');
        body { font-family: 'Inter', sans-serif; }
        .font-mono { font-family: 'JetBrains Mono', monospace; }
      `}</style>
    </div>
  );
}
