const axios = require('axios');

// ============================================
// SECURITY: INPUT VALIDATION
// ============================================
const validators = {
  isValidIP(ip) {
    if (!ip || typeof ip !== 'string') return false;
    const parts = ip.split('.');
    if (parts.length !== 4) return false;
    return parts.every(part => {
      const num = parseInt(part, 10);
      return num >= 0 && num <= 255 && String(num) === part;
    });
  },

  isValidDomain(domain) {
    if (!domain || typeof domain !== 'string') return false;
    if (domain.length > 253) return false;
    const domainRegex = /^(?!-)([a-zA-Z0-9-]{1,63}(?<!-)\.)+[a-zA-Z]{2,}$/;
    return domainRegex.test(domain);
  },

  isValidHash(hash) {
    if (!hash || typeof hash !== 'string') return false;
    return /^[a-fA-F0-9]{32}$|^[a-fA-F0-9]{40}$|^[a-fA-F0-9]{64}$/.test(hash);
  },

  sanitize(input) {
    if (!input || typeof input !== 'string') return '';
    return input.trim().substring(0, 500).replace(/[<>\"'&]/g, '');
  }
};

// ============================================
// SECURITY: RATE LIMITING
// ============================================
const rateLimiter = {
  requests: new Map(),
  limit: 60,
  windowMs: 60 * 1000,

  check(ip) {
    const now = Date.now();
    let requests = this.requests.get(ip) || [];
    requests = requests.filter(time => time > now - this.windowMs);
    
    if (requests.length >= this.limit) {
      return { allowed: false, remaining: 0, resetIn: Math.ceil((requests[0] + this.windowMs - now) / 1000) };
    }
    
    requests.push(now);
    this.requests.set(ip, requests);
    if (Math.random() < 0.01) this.cleanup();
    return { allowed: true, remaining: this.limit - requests.length };
  },

  cleanup() {
    const cutoff = Date.now() - this.windowMs;
    for (const [ip, requests] of this.requests.entries()) {
      const valid = requests.filter(time => time > cutoff);
      valid.length === 0 ? this.requests.delete(ip) : this.requests.set(ip, valid);
    }
  }
};

// ============================================
// SECURITY: HEADERS
// ============================================
function setSecurityHeaders(res) {
  const allowedOrigins = process.env.ALLOWED_ORIGINS?.split(',') || ['*'];
  res.setHeader('Access-Control-Allow-Origin', allowedOrigins[0]);
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, X-API-Key');
  res.setHeader('Access-Control-Max-Age', '86400');
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('X-XSS-Protection', '1; mode=block');
  res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
  res.setHeader('Cache-Control', 'no-store');
}

// ============================================
// SECURITY: AUTHENTICATION (Optional)
// ============================================
function authenticate(req) {
  const requiredKey = process.env.DASHBOARD_API_KEY;
  if (!requiredKey) return { authenticated: true };
  
  const providedKey = req.headers['x-api-key'] || req.query.apiKey;
  if (!providedKey) return { authenticated: false, reason: 'missing_api_key' };
  
  if (providedKey.length !== requiredKey.length) return { authenticated: false, reason: 'invalid_api_key' };
  let match = true;
  for (let i = 0; i < providedKey.length; i++) {
    if (providedKey[i] !== requiredKey[i]) match = false;
  }
  return match ? { authenticated: true } : { authenticated: false, reason: 'invalid_api_key' };
}

// ============================================
// SECURITY: SAFE ERROR RESPONSES
// ============================================
function safeError(error, source) {
  console.error(`[${source}] Error:`, error.message);
  const safeMessages = {
    'ABUSEIPDB_API_KEY not configured': 'AbuseIPDB feed not configured',
    'OTX_API_KEY not configured': 'AlienVault OTX feed not configured',
    'VIRUSTOTAL_API_KEY not configured': 'VirusTotal feed not configured',
    'SHODAN_API_KEY not configured': 'Shodan feed not configured',
  };
  return { source, error: safeMessages[error.message] || 'Service temporarily unavailable' };
}

// ============================================
// CACHE
// ============================================
const cache = {
  data: new Map(),
  maxSize: 1000,
  ttl: 5 * 60 * 1000,

  get(key) {
    const item = this.data.get(key);
    if (item && Date.now() - item.timestamp < this.ttl) return item.data;
    this.data.delete(key);
    return null;
  },

  set(key, data) {
    if (this.data.size >= this.maxSize) {
      const firstKey = this.data.keys().next().value;
      this.data.delete(firstKey);
    }
    this.data.set(key, { data, timestamp: Date.now() });
  }
};

// ============================================
// API INTEGRATIONS
// ============================================
async function abuseipdbCheck(ip) {
  if (!validators.isValidIP(ip)) throw new Error('Invalid IP format');
  const cacheKey = `abuseipdb:${ip}`;
  const cached = cache.get(cacheKey);
  if (cached) return cached;
  if (!process.env.ABUSEIPDB_API_KEY) throw new Error('ABUSEIPDB_API_KEY not configured');

  const response = await axios.get('https://api.abuseipdb.com/api/v2/check', {
    headers: { 'Key': process.env.ABUSEIPDB_API_KEY, 'Accept': 'application/json' },
    params: { ipAddress: ip, maxAgeInDays: 90, verbose: true },
    timeout: 10000
  });
  const data = response.data.data;
  const normalized = {
    source: 'AbuseIPDB', ip: data.ipAddress, abuseScore: data.abuseConfidenceScore,
    country: data.countryCode, isp: data.isp, totalReports: data.totalReports,
    lastReported: data.lastReportedAt, isTor: data.isTor
  };
  cache.set(cacheKey, normalized);
  return normalized;
}

async function abuseipdbBlacklist(limit = 100) {
  limit = Math.min(Math.max(parseInt(limit) || 100, 1), 500);
  const cacheKey = `abuseipdb:blacklist:${limit}`;
  const cached = cache.get(cacheKey);
  if (cached) return cached;
  if (!process.env.ABUSEIPDB_API_KEY) throw new Error('ABUSEIPDB_API_KEY not configured');

  const response = await axios.get('https://api.abuseipdb.com/api/v2/blacklist', {
    headers: { 'Key': process.env.ABUSEIPDB_API_KEY, 'Accept': 'application/json' },
    params: { confidenceMinimum: 90, limit },
    timeout: 10000
  });
  const normalized = response.data.data.map(item => ({
    source: 'AbuseIPDB', ip: item.ipAddress, abuseScore: item.abuseConfidenceScore,
    country: item.countryCode, lastReported: item.lastReportedAt
  }));
  cache.set(cacheKey, normalized);
  return normalized;
}

async function otxIndicator(type, indicator) {
  if (type === 'ip' && !validators.isValidIP(indicator)) throw new Error('Invalid IP format');
  if (type === 'domain' && !validators.isValidDomain(indicator)) throw new Error('Invalid domain format');
  if (type === 'hash' && !validators.isValidHash(indicator)) throw new Error('Invalid hash format');
  if (!['ip', 'domain', 'hash'].includes(type)) throw new Error('Invalid type');

  const cacheKey = `otx:${type}:${indicator}`;
  const cached = cache.get(cacheKey);
  if (cached) return cached;

  const headers = process.env.OTX_API_KEY ? { 'X-OTX-API-KEY': process.env.OTX_API_KEY } : {};
  const endpoints = { ip: `/indicators/IPv4/${indicator}/general`, domain: `/indicators/domain/${indicator}/general`, hash: `/indicators/file/${indicator}/general` };
  const response = await axios.get(`https://otx.alienvault.com/api/v1${endpoints[type]}`, { headers, timeout: 10000 });
  const data = response.data;

  const normalized = {
    source: 'AlienVault OTX', indicator, type, pulseCount: data.pulse_info?.count || 0,
    pulses: data.pulse_info?.pulses?.slice(0, 10).map(p => ({ id: p.id, name: p.name, tags: p.tags })) || [],
    country: data.country_code
  };
  cache.set(cacheKey, normalized);
  return normalized;
}

async function otxPulses(limit = 20) {
  limit = Math.min(Math.max(parseInt(limit) || 20, 1), 50);
  const cacheKey = `otx:pulses:${limit}`;
  const cached = cache.get(cacheKey);
  if (cached) return cached;
  if (!process.env.OTX_API_KEY) throw new Error('OTX_API_KEY not configured');

  const response = await axios.get('https://otx.alienvault.com/api/v1/pulses/subscribed', {
    headers: { 'X-OTX-API-KEY': process.env.OTX_API_KEY }, params: { limit }, timeout: 10000
  });
  const normalized = response.data.results.map(p => ({
    source: 'AlienVault OTX', id: p.id, name: validators.sanitize(p.name),
    description: validators.sanitize(p.description?.substring(0, 500)),
    author: validators.sanitize(p.author_name), created: p.created, modified: p.modified,
    tags: p.tags?.slice(0, 10), tlp: p.TLP, indicatorCount: p.indicator_count
  }));
  cache.set(cacheKey, normalized);
  return normalized;
}

async function vtAnalyze(type, value) {
  if (type === 'ip' && !validators.isValidIP(value)) throw new Error('Invalid IP format');
  if (type === 'domain' && !validators.isValidDomain(value)) throw new Error('Invalid domain format');
  if (type === 'hash' && !validators.isValidHash(value)) throw new Error('Invalid hash format');
  if (!['ip', 'domain', 'hash'].includes(type)) throw new Error('Invalid type');

  const cacheKey = `vt:${type}:${value}`;
  const cached = cache.get(cacheKey);
  if (cached) return cached;
  if (!process.env.VIRUSTOTAL_API_KEY) throw new Error('VIRUSTOTAL_API_KEY not configured');

  const endpoints = { ip: `/ip_addresses/${value}`, domain: `/domains/${value}`, hash: `/files/${value}` };
  const response = await axios.get(`https://www.virustotal.com/api/v3${endpoints[type]}`, {
    headers: { 'x-apikey': process.env.VIRUSTOTAL_API_KEY }, timeout: 10000
  });
  const data = response.data.data;
  const stats = data.attributes.last_analysis_stats;

  const normalized = {
    source: 'VirusTotal', [type]: value, type, malicious: stats.malicious,
    suspicious: stats.suspicious, harmless: stats.harmless, undetected: stats.undetected,
    totalEngines: Object.values(stats).reduce((a, b) => a + b, 0),
    country: data.attributes.country, reputation: data.attributes.reputation
  };
  cache.set(cacheKey, normalized);
  return normalized;
}

async function urlhausRecent(limit = 100) {
  limit = Math.min(Math.max(parseInt(limit) || 100, 1), 500);
  const cacheKey = `urlhaus:recent:${limit}`;
  const cached = cache.get(cacheKey);
  if (cached) return cached;

  const response = await axios.post('https://urlhaus-api.abuse.ch/v1/urls/recent/',
    `limit=${limit}`, { headers: { 'Content-Type': 'application/x-www-form-urlencoded' }, timeout: 10000 });
  const normalized = response.data.urls?.map(u => ({
    source: 'URLhaus', id: u.id, url: u.url, urlStatus: u.url_status,
    host: u.host, dateAdded: u.date_added, threat: u.threat, tags: u.tags?.slice(0, 10)
  })) || [];
  cache.set(cacheKey, normalized);
  return normalized;
}

async function urlhausHost(host) {
  if (!validators.isValidIP(host) && !validators.isValidDomain(host)) throw new Error('Invalid host format');
  const cacheKey = `urlhaus:host:${host}`;
  const cached = cache.get(cacheKey);
  if (cached) return cached;

  const response = await axios.post('https://urlhaus-api.abuse.ch/v1/host/',
    `host=${encodeURIComponent(host)}`, { headers: { 'Content-Type': 'application/x-www-form-urlencoded' }, timeout: 10000 });
  if (response.data.query_status === 'no_results') return { source: 'URLhaus', found: false, host };

  const normalized = {
    source: 'URLhaus', found: true, host: response.data.host, urlCount: response.data.url_count,
    urls: response.data.urls?.slice(0, 20).map(u => ({ url: u.url, status: u.url_status, threat: u.threat, tags: u.tags?.slice(0, 5) }))
  };
  cache.set(cacheKey, normalized);
  return normalized;
}

async function vtRecentMalware(limit = 20) {
  limit = Math.min(Math.max(parseInt(limit) || 20, 1), 40);
  const cacheKey = `vt:recent:${limit}`;
  const cached = cache.get(cacheKey);
  if (cached) return cached;
  if (!process.env.VIRUSTOTAL_API_KEY) throw new Error('VIRUSTOTAL_API_KEY not configured');

  // Use VirusTotal search API to find recent malicious files
  const response = await axios.get('https://www.virustotal.com/api/v3/intelligence/search', {
    headers: { 'x-apikey': process.env.VIRUSTOTAL_API_KEY },
    params: {
      query: 'type:file positives:10+',
      limit,
      order: 'creation_date-'
    },
    timeout: 10000
  });

  const normalized = response.data.data?.map(file => ({
    source: 'VirusTotal',
    id: file.id,
    hash: file.attributes.sha256,
    type: file.attributes.type_description || 'Malicious File',
    name: file.attributes.meaningful_name || file.attributes.names?.[0] || 'Unknown',
    malicious: file.attributes.last_analysis_stats?.malicious || 0,
    totalVendors: file.attributes.last_analysis_stats ?
      Object.values(file.attributes.last_analysis_stats).reduce((a, b) => a + b, 0) : 0,
    firstSeen: file.attributes.first_submission_date,
    tags: file.attributes.tags?.slice(0, 10) || []
  })) || [];

  cache.set(cacheKey, normalized);
  return normalized;
}

async function shodanVulnerable(limit = 20) {
  limit = Math.min(Math.max(parseInt(limit) || 20, 1), 100);
  const cacheKey = `shodan:vulnerable:${limit}`;
  const cached = cache.get(cacheKey);
  if (cached) return cached;
  if (!process.env.SHODAN_API_KEY) throw new Error('SHODAN_API_KEY not configured');

  // Search for systems with known CVEs or vulnerable services
  const queries = [
    'vuln:CVE-2023',
    'vuln:CVE-2024',
    'port:445 os:windows',  // SMB on Windows
    'port:3389 os:windows', // RDP exposed
  ];

  const results = [];
  for (const query of queries.slice(0, 2)) { // Limit to 2 queries to avoid rate limits
    try {
      const response = await axios.get('https://api.shodan.io/shodan/host/search', {
        params: {
          key: process.env.SHODAN_API_KEY,
          query,
          minify: true
        },
        timeout: 10000
      });

      response.data.matches?.slice(0, Math.ceil(limit / 2)).forEach(match => {
        results.push({
          source: 'Shodan',
          ip: match.ip_str,
          port: match.port,
          org: match.org || 'Unknown',
          country: match.location?.country_name || match.location?.country_code || 'Unknown',
          product: match.product || 'Unknown Service',
          vulns: match.vulns || [],
          timestamp: match.timestamp ? new Date(match.timestamp).getTime() : Date.now()
        });
      });
    } catch (error) {
      console.error(`Shodan query error for "${query}":`, error.message);
    }
  }

  const normalized = results.slice(0, limit);
  cache.set(cacheKey, normalized);
  return normalized;
}

async function shodanIP(ip) {
  if (!validators.isValidIP(ip)) throw new Error('Invalid IP format');
  const cacheKey = `shodan:ip:${ip}`;
  const cached = cache.get(cacheKey);
  if (cached) return cached;
  if (!process.env.SHODAN_API_KEY) throw new Error('SHODAN_API_KEY not configured');

  const response = await axios.get(`https://api.shodan.io/shodan/host/${ip}`, { params: { key: process.env.SHODAN_API_KEY }, timeout: 10000 });
  const data = response.data;
  const normalized = {
    source: 'Shodan', ip: data.ip_str, hostnames: data.hostnames?.slice(0, 10),
    country: data.country_name, city: data.city, org: data.org,
    ports: data.ports?.slice(0, 50), vulns: data.vulns?.slice(0, 20),
    services: data.data?.slice(0, 20).map(s => ({ port: s.port, product: s.product, version: s.version }))
  };
  cache.set(cacheKey, normalized);
  return normalized;
}

async function threatfoxRecent(days = 3, limit = 100) {
  days = Math.min(Math.max(parseInt(days) || 3, 1), 7);
  limit = Math.min(Math.max(parseInt(limit) || 100, 1), 500);
  const cacheKey = `threatfox:recent:${days}:${limit}`;
  const cached = cache.get(cacheKey);
  if (cached) return cached;

  const response = await axios.post('https://threatfox-api.abuse.ch/api/v1', { query: 'get_iocs', days }, { timeout: 10000 });
  const normalized = response.data.data?.slice(0, limit).map(ioc => ({
    source: 'ThreatFox', id: ioc.id, ioc: ioc.ioc, iocType: ioc.ioc_type, threatType: ioc.threat_type,
    malware: ioc.malware, malwarePrintable: validators.sanitize(ioc.malware_printable),
    confidence: ioc.confidence_level, firstSeen: ioc.first_seen, tags: ioc.tags?.slice(0, 10)
  })) || [];
  cache.set(cacheKey, normalized);
  return normalized;
}

async function threatfoxSearch(searchTerm) {
  searchTerm = validators.sanitize(searchTerm);
  if (!searchTerm || searchTerm.length < 3) throw new Error('Search term must be at least 3 characters');
  const cacheKey = `threatfox:search:${searchTerm}`;
  const cached = cache.get(cacheKey);
  if (cached) return cached;

  const response = await axios.post('https://threatfox-api.abuse.ch/api/v1', { query: 'search_ioc', search_term: searchTerm }, { timeout: 10000 });
  if (response.data.query_status !== 'ok') return { source: 'ThreatFox', found: false, searchTerm };

  const normalized = {
    source: 'ThreatFox', found: true,
    results: response.data.data?.slice(0, 100).map(ioc => ({
      id: ioc.id, ioc: ioc.ioc, iocType: ioc.ioc_type, threatType: ioc.threat_type,
      malware: validators.sanitize(ioc.malware_printable), confidence: ioc.confidence_level, tags: ioc.tags?.slice(0, 10)
    }))
  };
  cache.set(cacheKey, normalized);
  return normalized;
}

async function cisaKevCatalog(limit = 100) {
  limit = Math.min(Math.max(parseInt(limit) || 100, 1), 500);
  const cacheKey = `cisa:kev:${limit}`;
  const cached = cache.get(cacheKey);
  if (cached) return cached;

  const response = await axios.get('https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json', { timeout: 15000 });
  const vulnerabilities = response.data.vulnerabilities || [];

  const normalized = vulnerabilities.slice(0, limit).map(vuln => ({
    source: 'CISA KEV',
    cveId: vuln.cveID,
    vendorProject: validators.sanitize(vuln.vendorProject),
    product: validators.sanitize(vuln.product),
    vulnerabilityName: validators.sanitize(vuln.vulnerabilityName),
    dateAdded: vuln.dateAdded,
    shortDescription: validators.sanitize(vuln.shortDescription),
    requiredAction: validators.sanitize(vuln.requiredAction),
    dueDate: vuln.dueDate,
    knownRansomwareCampaignUse: vuln.knownRansomwareCampaignUse,
    notes: vuln.notes
  }));

  cache.set(cacheKey, normalized);
  return normalized;
}

async function cisaKevSearch(cveId) {
  cveId = validators.sanitize(cveId).toUpperCase();
  if (!cveId.match(/^CVE-\d{4}-\d{4,}$/)) throw new Error('Invalid CVE ID format');

  const cacheKey = `cisa:kev:search:${cveId}`;
  const cached = cache.get(cacheKey);
  if (cached) return cached;

  const response = await axios.get('https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json', { timeout: 15000 });
  const vulnerabilities = response.data.vulnerabilities || [];

  const found = vulnerabilities.find(v => v.cveID === cveId);

  if (!found) return { source: 'CISA KEV', found: false, cveId };

  const normalized = {
    source: 'CISA KEV',
    found: true,
    cveId: found.cveID,
    vendorProject: validators.sanitize(found.vendorProject),
    product: validators.sanitize(found.product),
    vulnerabilityName: validators.sanitize(found.vulnerabilityName),
    dateAdded: found.dateAdded,
    shortDescription: validators.sanitize(found.shortDescription),
    requiredAction: validators.sanitize(found.requiredAction),
    dueDate: found.dueDate,
    knownRansomwareCampaignUse: found.knownRansomwareCampaignUse,
    notes: found.notes
  };

  cache.set(cacheKey, normalized);
  return normalized;
}

// ============================================
// ROUTE HANDLERS
// ============================================
async function handleHealth(req, res) {
  res.json({
    status: 'healthy', timestamp: new Date().toISOString(), version: '1.0.0',
    feeds: {
      abuseipdb: !!process.env.ABUSEIPDB_API_KEY, otx: !!process.env.OTX_API_KEY,
      virustotal: !!process.env.VIRUSTOTAL_API_KEY, shodan: !!process.env.SHODAN_API_KEY,
      urlhaus: true, threatfox: true
    }
  });
}

async function handleFeeds(req, res) {
  res.json({
    feeds: [
      { name: 'AbuseIPDB', configured: !!process.env.ABUSEIPDB_API_KEY, status: process.env.ABUSEIPDB_API_KEY ? 'connected' : 'api_key_required', free: true, rateLimit: '1,000/day', docs: 'https://docs.abuseipdb.com/' },
      { name: 'AlienVault OTX', configured: !!process.env.OTX_API_KEY, status: process.env.OTX_API_KEY ? 'connected' : 'api_key_required', free: true, rateLimit: 'Unlimited', docs: 'https://otx.alienvault.com/api' },
      { name: 'VirusTotal', configured: !!process.env.VIRUSTOTAL_API_KEY, status: process.env.VIRUSTOTAL_API_KEY ? 'connected' : 'api_key_required', free: true, rateLimit: '500/day', docs: 'https://docs.virustotal.com/' },
      { name: 'Shodan', configured: !!process.env.SHODAN_API_KEY, status: process.env.SHODAN_API_KEY ? 'connected' : 'api_key_required', free: true, rateLimit: 'Limited', docs: 'https://developer.shodan.io/api' },
      { name: 'URLhaus', configured: true, status: 'connected', free: true, rateLimit: 'Unlimited', docs: 'https://urlhaus-api.abuse.ch/' },
      { name: 'ThreatFox', configured: true, status: 'connected', free: true, rateLimit: 'Unlimited', docs: 'https://threatfox.abuse.ch/api/' },
      { name: 'CISA KEV', configured: true, status: 'connected', free: true, rateLimit: 'Unlimited', docs: 'https://www.cisa.gov/known-exploited-vulnerabilities-catalog' }
    ]
  });
}

async function handleThreats(req, res) {
  const threats = [];
  const errors = [];

  const fetches = [
    urlhausRecent(50).then(urls => urls.forEach(u => threats.push({
      id: `urlhaus-${u.id}`, source: 'URLhaus', type: 'Malware URL', name: u.threat || 'Malicious URL',
      indicator: u.url, host: u.host, severity: u.threat === 'malware_download' ? 'critical' : 'high',
      timestamp: new Date(u.dateAdded).getTime(), tags: u.tags
    }))).catch(e => errors.push(safeError(e, 'URLhaus'))),

    threatfoxRecent(3, 50).then(iocs => iocs.forEach(ioc => threats.push({
      id: `threatfox-${ioc.id}`, source: 'ThreatFox', type: ioc.threatType,
      name: ioc.malwarePrintable || ioc.malware, indicator: ioc.ioc,
      severity: ioc.confidence >= 75 ? 'critical' : ioc.confidence >= 50 ? 'high' : 'medium',
      timestamp: new Date(ioc.firstSeen).getTime(), tags: ioc.tags, confidence: ioc.confidence
    }))).catch(e => errors.push(safeError(e, 'ThreatFox')))
  ];

  if (process.env.ABUSEIPDB_API_KEY) {
    fetches.push(abuseipdbBlacklist(50).then(ips => ips.forEach(ip => threats.push({
      id: `abuseipdb-${ip.ip}`, source: 'AbuseIPDB', type: 'Malicious IP',
      name: `Abusive IP (${ip.abuseScore}% confidence)`, indicator: ip.ip, country: ip.country,
      severity: ip.abuseScore >= 90 ? 'critical' : ip.abuseScore >= 70 ? 'high' : 'medium',
      timestamp: new Date(ip.lastReported).getTime(), abuseScore: ip.abuseScore
    }))).catch(e => errors.push(safeError(e, 'AbuseIPDB'))));
  }

  if (process.env.OTX_API_KEY) {
    fetches.push(otxPulses(20).then(pulses => pulses.forEach(p => threats.push({
      id: `otx-${p.id}`, source: 'AlienVault OTX', type: 'Threat Intel Pulse', name: p.name,
      description: p.description, severity: p.tlp === 'red' ? 'critical' : p.tlp === 'amber' ? 'high' : 'medium',
      timestamp: new Date(p.modified || p.created).getTime(), tags: p.tags, author: p.author
    }))).catch(e => errors.push(safeError(e, 'AlienVault OTX'))));
  }

  if (process.env.VIRUSTOTAL_API_KEY) {
    fetches.push(vtRecentMalware(15).then(files => files.forEach(file => threats.push({
      id: `vt-${file.id}`, source: 'VirusTotal', type: file.type,
      name: file.name, indicator: file.hash,
      severity: file.malicious >= 40 ? 'critical' : file.malicious >= 20 ? 'high' : 'medium',
      timestamp: file.firstSeen ? file.firstSeen * 1000 : Date.now(),
      tags: file.tags,
      malicious: file.malicious,
      totalVendors: file.totalVendors
    }))).catch(e => errors.push(safeError(e, 'VirusTotal'))));
  }

  if (process.env.SHODAN_API_KEY) {
    fetches.push(shodanVulnerable(15).then(hosts => hosts.forEach(host => threats.push({
      id: `shodan-${host.ip}-${host.port}`, source: 'Shodan', type: 'Vulnerable Host',
      name: `${host.product} on ${host.ip}:${host.port}`,
      indicator: host.ip, country: host.country, org: host.org,
      severity: host.vulns?.length > 0 ? 'critical' : 'medium',
      timestamp: host.timestamp || Date.now(),
      tags: host.vulns?.slice(0, 5) || [],
      port: host.port,
      vulns: host.vulns
    }))).catch(e => errors.push(safeError(e, 'Shodan'))));
  }

  await Promise.all(fetches);
  threats.sort((a, b) => b.timestamp - a.timestamp);
  res.json({ timestamp: new Date().toISOString(), totalThreats: threats.length, threats, errors: errors.length > 0 ? errors : undefined });
}

async function handleSearch(req, res) {
  if (req.method !== 'POST') return res.status(405).json({ error: 'POST method required' });

  const { indicator, type } = req.body || {};
  if (!indicator) return res.status(400).json({ error: 'Indicator required' });

  const sanitizedIndicator = validators.sanitize(indicator);
  if (sanitizedIndicator.length < 3) return res.status(400).json({ error: 'Indicator too short' });

  const results = { indicator: sanitizedIndicator, type, timestamp: new Date().toISOString(), sources: [] };
  const searches = [];

  const isIP = validators.isValidIP(sanitizedIndicator);
  const isDomain = validators.isValidDomain(sanitizedIndicator);
  const isHash = validators.isValidHash(sanitizedIndicator);

  if (type === 'ip' || (!type && isIP)) {
    if (process.env.ABUSEIPDB_API_KEY) searches.push(abuseipdbCheck(sanitizedIndicator).then(r => results.sources.push(r)).catch(e => results.sources.push(safeError(e, 'AbuseIPDB'))));
    if (process.env.VIRUSTOTAL_API_KEY) searches.push(vtAnalyze('ip', sanitizedIndicator).then(r => results.sources.push(r)).catch(e => results.sources.push(safeError(e, 'VirusTotal'))));
    if (process.env.SHODAN_API_KEY) searches.push(shodanIP(sanitizedIndicator).then(r => results.sources.push(r)).catch(e => results.sources.push(safeError(e, 'Shodan'))));
    if (process.env.OTX_API_KEY) searches.push(otxIndicator('ip', sanitizedIndicator).then(r => results.sources.push(r)).catch(e => results.sources.push(safeError(e, 'AlienVault OTX'))));
    searches.push(urlhausHost(sanitizedIndicator).then(r => results.sources.push(r)).catch(e => results.sources.push(safeError(e, 'URLhaus'))));
  }

  if (type === 'domain' || (!type && isDomain)) {
    if (process.env.VIRUSTOTAL_API_KEY) searches.push(vtAnalyze('domain', sanitizedIndicator).then(r => results.sources.push(r)).catch(e => results.sources.push(safeError(e, 'VirusTotal'))));
    if (process.env.OTX_API_KEY) searches.push(otxIndicator('domain', sanitizedIndicator).then(r => results.sources.push(r)).catch(e => results.sources.push(safeError(e, 'AlienVault OTX'))));
    searches.push(urlhausHost(sanitizedIndicator).then(r => results.sources.push(r)).catch(e => results.sources.push(safeError(e, 'URLhaus'))));
  }

  if (type === 'hash' || (!type && isHash)) {
    if (process.env.VIRUSTOTAL_API_KEY) searches.push(vtAnalyze('hash', sanitizedIndicator).then(r => results.sources.push(r)).catch(e => results.sources.push(safeError(e, 'VirusTotal'))));
    if (process.env.OTX_API_KEY) searches.push(otxIndicator('hash', sanitizedIndicator).then(r => results.sources.push(r)).catch(e => results.sources.push(safeError(e, 'AlienVault OTX'))));
  }

  searches.push(threatfoxSearch(sanitizedIndicator).then(r => results.sources.push(r)).catch(e => results.sources.push(safeError(e, 'ThreatFox'))));

  await Promise.all(searches);
  res.json(results);
}

async function handleCVEs(req, res) {
  try {
    const limit = parseInt(req.query.limit) || 100;
    const cves = await cisaKevCatalog(limit);

    res.json({
      timestamp: new Date().toISOString(),
      totalCVEs: cves.length,
      catalogInfo: {
        title: 'CISA Known Exploited Vulnerabilities Catalog',
        catalogVersion: new Date().toISOString().split('T')[0],
        count: cves.length
      },
      cves
    });
  } catch (error) {
    console.error('CVE fetch error:', error);
    res.status(500).json({ error: 'Failed to fetch CVE catalog' });
  }
}

async function handleCVESearch(req, res) {
  if (req.method !== 'POST') return res.status(405).json({ error: 'POST method required' });

  const { cveId } = req.body || {};
  if (!cveId) return res.status(400).json({ error: 'CVE ID required' });

  try {
    const result = await cisaKevSearch(cveId);
    res.json(result);
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
}

// ============================================
// CYBERSECURITY NEWS FEEDS
// ============================================
const NEWS_SOURCES = [
  {
    name: 'The Hacker News',
    url: 'https://feeds.feedburner.com/TheHackersNews',
    description: 'Breaking cybersecurity news and analysis',
    category: 'news'
  },
  {
    name: 'Bleeping Computer',
    url: 'https://www.bleepingcomputer.com/feed/',
    description: 'Technology news and security alerts',
    category: 'news'
  },
  {
    name: 'Krebs on Security',
    url: 'https://krebsonsecurity.com/feed/',
    description: 'In-depth security news and investigation',
    category: 'blog'
  },
  {
    name: 'CISA Alerts',
    url: 'https://www.cisa.gov/cybersecurity-advisories/all.xml',
    description: 'Official US government cybersecurity advisories',
    category: 'advisory'
  },
  {
    name: 'Threatpost',
    url: 'https://threatpost.com/feed/',
    description: 'Enterprise security news',
    category: 'news'
  },
  {
    name: 'SecurityWeek',
    url: 'https://www.securityweek.com/feed/',
    description: 'Security news and analysis',
    category: 'news'
  },
  {
    name: 'Dark Reading',
    url: 'https://www.darkreading.com/rss.xml',
    description: 'Cybersecurity intelligence and insights',
    category: 'news'
  }
];

async function parseRSSFeed(source) {
  try {
    const response = await axios.get(source.url, {
      timeout: 10000,
      headers: { 'User-Agent': 'Mozilla/5.0 (compatible; ThreatIntelDashboard/1.0)' }
    });

    const xml = response.data;
    const articles = [];

    // Simple RSS/Atom parser (extract items/entries)
    const itemRegex = /<item>[\s\S]*?<\/item>/gi;
    const entryRegex = /<entry>[\s\S]*?<\/entry>/gi;

    const items = xml.match(itemRegex) || xml.match(entryRegex) || [];

    for (const item of items.slice(0, 10)) { // Limit to 10 articles per source
      // Extract fields using regex (simple parser)
      const title = item.match(/<title(?:[^>]*)>(?:<!\[CDATA\[)?(.*?)(?:\]\]>)?<\/title>/i)?.[1]?.trim() || '';
      const link = item.match(/<link(?:[^>]*)>(?:<!\[CDATA\[)?(.*?)(?:\]\]>)?<\/link>/i)?.[1]?.trim() ||
                   item.match(/<link[^>]*href=["']([^"']+)["']/i)?.[1]?.trim() || '';
      const description = item.match(/<description(?:[^>]*)>(?:<!\[CDATA\[)?(.*?)(?:\]\]>)?<\/description>/i)?.[1]?.trim() ||
                         item.match(/<summary(?:[^>]*)>(?:<!\[CDATA\[)?(.*?)(?:\]\]>)?<\/summary>/i)?.[1]?.trim() || '';
      const pubDate = item.match(/<pubDate(?:[^>]*)>(.*?)<\/pubDate>/i)?.[1]?.trim() ||
                     item.match(/<published(?:[^>]*)>(.*?)<\/published>/i)?.[1]?.trim() ||
                     item.match(/<updated(?:[^>]*)>(.*?)<\/updated>/i)?.[1]?.trim() || '';

      if (title && link) {
        // Clean HTML tags from description
        const cleanDescription = description.replace(/<[^>]*>/g, '').replace(/&[^;]+;/g, ' ').trim().substring(0, 300);

        articles.push({
          source: source.name,
          category: source.category,
          title: title.replace(/&[^;]+;/g, ' ').trim(),
          link,
          description: cleanDescription,
          publishedAt: pubDate ? new Date(pubDate).getTime() : Date.now()
        });
      }
    }

    return articles;
  } catch (error) {
    console.error(`Error fetching ${source.name}:`, error.message);
    return [];
  }
}

async function fetchCyberNews(limit = 50) {
  const cacheKey = 'news:all';
  const cached = cache.get(cacheKey);
  if (cached) return cached;

  const allArticles = [];
  const fetchPromises = NEWS_SOURCES.map(source =>
    parseRSSFeed(source).then(articles => allArticles.push(...articles))
  );

  await Promise.all(fetchPromises);

  // Sort by published date (newest first)
  allArticles.sort((a, b) => b.publishedAt - a.publishedAt);

  // Limit results
  const limitedArticles = allArticles.slice(0, Math.min(limit, 100));

  cache.set(cacheKey, limitedArticles);
  return limitedArticles;
}

async function handleNews(req, res) {
  try {
    const limit = parseInt(req.query.limit) || 50;
    const articles = await fetchCyberNews(limit);

    res.json({
      timestamp: new Date().toISOString(),
      totalArticles: articles.length,
      sources: NEWS_SOURCES.map(s => ({ name: s.name, category: s.category, description: s.description })),
      articles
    });
  } catch (error) {
    console.error('News fetch error:', error);
    res.status(500).json({ error: 'Failed to fetch cybersecurity news' });
  }
}

// ============================================
// MAIN HANDLER
// ============================================
module.exports = async (req, res) => {
  setSecurityHeaders(res);
  if (req.method === 'OPTIONS') return res.status(200).end();

  // Rate limiting
  const clientIP = req.headers['x-forwarded-for']?.split(',')[0]?.trim() || req.headers['x-real-ip'] || 'unknown';
  const rateCheck = rateLimiter.check(clientIP);
  res.setHeader('X-RateLimit-Limit', rateLimiter.limit);
  res.setHeader('X-RateLimit-Remaining', rateCheck.remaining);

  if (!rateCheck.allowed) {
    res.setHeader('Retry-After', rateCheck.resetIn);
    return res.status(429).json({ error: 'Rate limit exceeded', retryAfter: rateCheck.resetIn });
  }

  // Authentication
  const auth = authenticate(req);
  if (!auth.authenticated) {
    return res.status(401).json({
      error: 'Unauthorized',
      message: auth.reason === 'missing_api_key' ? 'API key required. Include X-API-Key header.' : 'Invalid API key'
    });
  }

  // Routing
  const endpoint = req.query.endpoint || 'health';

  try {
    switch (endpoint) {
      case 'health': return handleHealth(req, res);
      case 'feeds': return handleFeeds(req, res);
      case 'threats': return handleThreats(req, res);
      case 'search': return handleSearch(req, res);
      case 'cves': return handleCVEs(req, res);
      case 'cve-search': return handleCVESearch(req, res);
      case 'news': return handleNews(req, res);
      default: return res.status(404).json({ error: 'Endpoint not found', available: ['health', 'feeds', 'threats', 'search', 'cves', 'cve-search', 'news'] });
    }
  } catch (error) {
    console.error('Unhandled error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
};
