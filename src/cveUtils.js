// CVE and KEV (Known Exploited Vulnerabilities) Utilities

// Sample KEV data structure (would be fetched from CISA KEV catalog)
// https://www.cisa.gov/known-exploited-vulnerabilities-catalog
export const SAMPLE_KEVS = {
  'CVE-2023-4966': {
    cveId: 'CVE-2023-4966',
    vendorProject: 'Citrix',
    product: 'NetScaler ADC, NetScaler Gateway',
    vulnerabilityName: 'Citrix NetScaler ADC and NetScaler Gateway Buffer Overflow Vulnerability',
    dateAdded: '2023-10-25',
    shortDescription: 'Citrix NetScaler ADC and NetScaler Gateway contain a buffer overflow vulnerability that allows for unauthenticated remote code execution.',
    requiredAction: 'Apply mitigations per vendor instructions or discontinue use of the product if mitigations are unavailable.',
    dueDate: '2023-11-15',
    knownRansomwareCampaignUse: 'Known',
    notes: 'https://support.citrix.com/article/CTX579459',
    cvss: 9.8,
    exploited: true,
    trending: true
  },
  'CVE-2024-3400': {
    cveId: 'CVE-2024-3400',
    vendorProject: 'Palo Alto Networks',
    product: 'PAN-OS',
    vulnerabilityName: 'Palo Alto Networks PAN-OS Command Injection Vulnerability',
    dateAdded: '2024-04-12',
    shortDescription: 'Palo Alto Networks PAN-OS contains a command injection vulnerability in the GlobalProtect feature that allows for unauthenticated remote code execution.',
    requiredAction: 'Apply mitigations per vendor instructions immediately.',
    dueDate: '2024-05-03',
    knownRansomwareCampaignUse: 'Known',
    notes: 'https://security.paloaltonetworks.com/CVE-2024-3400',
    cvss: 10.0,
    exploited: true,
    trending: true
  },
  'CVE-2023-27997': {
    cveId: 'CVE-2023-27997',
    vendorProject: 'Fortinet',
    product: 'FortiOS, FortiProxy',
    vulnerabilityName: 'Fortinet FortiOS and FortiProxy Heap-Based Buffer Overflow Vulnerability',
    dateAdded: '2023-06-13',
    shortDescription: 'Fortinet FortiOS and FortiProxy contain a heap-based buffer overflow vulnerability that allows for remote code execution.',
    requiredAction: 'Apply updates per vendor instructions.',
    dueDate: '2023-07-04',
    knownRansomwareCampaignUse: 'Known',
    notes: 'https://www.fortiguard.com/psirt/FG-IR-23-097',
    cvss: 9.8,
    exploited: true,
    trending: false
  }
};

// Vulnerability breakdown structure
export function generateVulnerabilityBreakdown(cve) {
  const breakdowns = {
    'CVE-2023-4966': {
      flaw: 'Improper bounds checking (Buffer Overflow) in the NetScaler packet processing engine (nsppe binary), specifically within the OpenID Connect (OIDC) flow.',
      mechanism: 'An attacker sends a specially crafted HTTP GET request with an oversized header field to the management interface or virtual IP (VIP).',
      outcome: 'This triggers a heap overflow before authentication, allowing the attacker to overwrite memory, gain execution control, and achieve root shell access on the NetScaler appliance.',
      impact: 'Full device compromise, potential for credential harvesting (stealing VPN login details), session hijacking, and a launchpad for massive lateral movement into the internal network.',
      affectedVersions: ['NetScaler ADC 14.1 < 14.1-12.35', 'NetScaler ADC 13.1 < 13.1-51.15', 'NetScaler ADC 13.0 < 13.0-92.21', 'NetScaler Gateway 14.1 < 14.1-12.35', 'NetScaler Gateway 13.1 < 13.1-51.15'],
      attackVector: 'Network',
      attackComplexity: 'Low',
      privilegesRequired: 'None',
      userInteraction: 'None'
    },
    'CVE-2024-3400': {
      flaw: 'Command injection vulnerability in the GlobalProtect feature of PAN-OS allowing arbitrary code execution with root privileges.',
      mechanism: 'An unauthenticated attacker exploits improper input validation in the GlobalProtect gateway by sending malicious requests that inject commands.',
      outcome: 'Successful exploitation grants the attacker complete control over the firewall with root-level access, bypassing all authentication mechanisms.',
      impact: 'Complete firewall compromise, ability to disable security policies, exfiltrate sensitive configuration and traffic data, establish persistent backdoors, and pivot to internal network segments.',
      affectedVersions: ['PAN-OS 10.2.0 - 10.2.8', 'PAN-OS 11.0.0 - 11.0.3', 'PAN-OS 11.1.0 - 11.1.1'],
      attackVector: 'Network',
      attackComplexity: 'Low',
      privilegesRequired: 'None',
      userInteraction: 'None'
    },
    'CVE-2023-27997': {
      flaw: 'Heap-based buffer overflow vulnerability in the SSL VPN pre-authentication process of FortiOS and FortiProxy.',
      mechanism: 'An attacker sends specially crafted SSL VPN packets that overflow a heap buffer during pre-authentication processing.',
      outcome: 'Memory corruption leads to remote code execution before any user authentication, giving attackers complete control of the appliance.',
      impact: 'Full device takeover, VPN credential harvesting, man-in-the-middle attacks on VPN traffic, and lateral movement into protected network segments.',
      affectedVersions: ['FortiOS 7.2.0 - 7.2.4', 'FortiOS 7.0.0 - 7.0.11', 'FortiOS 6.4.0 - 6.4.12', 'FortiProxy 7.2.0 - 7.2.3', 'FortiProxy 7.0.0 - 7.0.10'],
      attackVector: 'Network',
      attackComplexity: 'Low',
      privilegesRequired: 'None',
      userInteraction: 'None'
    }
  };

  return breakdowns[cve.cveId] || {
    flaw: 'Security vulnerability allowing unauthorized access or code execution.',
    mechanism: 'Attacker exploits weakness in software implementation or configuration.',
    outcome: 'Successful exploitation may lead to unauthorized access, data exposure, or system compromise.',
    impact: 'Potential for data breach, service disruption, or unauthorized system access.',
    affectedVersions: ['Check vendor advisory for specific versions'],
    attackVector: 'Varies',
    attackComplexity: 'Varies',
    privilegesRequired: 'Varies',
    userInteraction: 'Varies'
  };
}

// Generate mitigation and action items for CVE
export function generateCVEMitigation(cve) {
  const mitigations = {
    'CVE-2023-4966': {
      emergencyPatching: {
        title: 'Emergency Patching',
        description: 'Apply the firmware build released November 14, 2023 immediately.',
        patches: [
          'NetScaler ADC 14.1-12.35 or later',
          'NetScaler ADC 13.1-51.15 or later',
          'NetScaler ADC 13.0-92.21 or later',
          'NetScaler Gateway 14.1-12.35 or later',
          'NetScaler Gateway 13.1-51.15 or later'
        ],
        priority: 'critical',
        timeframe: 'Immediate (within 24 hours)'
      },
      immediateAction: {
        title: 'Immediate Action',
        description: 'If patching is delayed, remove the appliance from public internet exposure or implement strict network segmentation.',
        actions: [
          'Remove NetScaler from direct internet exposure',
          'Implement WAF rules to filter malicious requests',
          'Enable additional logging and monitoring',
          'Review firewall rules restricting access to management interface',
          'Disable OIDC if not required'
        ],
        priority: 'high',
        timeframe: 'Within 4 hours'
      },
      postPatch: {
        title: 'Post-Patch Actions',
        description: 'After patching, perform security hardening and incident validation.',
        actions: [
          'Force disconnect of all active user sessions',
          'Require re-authentication for all users',
          'Rotate service account credentials (LDAP/AD)',
          'Review access logs for signs of compromise',
          'Scan for indicators of compromise (IOCs)',
          'Update security monitoring rules',
          'Document patching in change management system'
        ],
        priority: 'high',
        timeframe: 'Within 72 hours post-patch'
      },
      detection: {
        title: 'Detection & Monitoring',
        description: 'Implement enhanced monitoring to detect exploitation attempts.',
        iocs: [
          'Unusual traffic to /oauth/idp/.well-known/openid-configuration',
          'Abnormal nsppe process memory usage',
          'Unexpected outbound connections from NetScaler',
          'New user accounts or modified admin credentials',
          'Suspicious files in /var/tmp/ or /tmp/ directories'
        ],
        priority: 'high'
      }
    },
    'CVE-2024-3400': {
      emergencyPatching: {
        title: 'Emergency Patching',
        description: 'Apply hotfix immediately - actively exploited in the wild.',
        patches: [
          'PAN-OS 11.1.2-h3 or later',
          'PAN-OS 11.0.4-h1 or later',
          'PAN-OS 10.2.9-h1 or later'
        ],
        priority: 'critical',
        timeframe: 'Immediate (within 4 hours)'
      },
      immediateAction: {
        title: 'Immediate Action',
        description: 'Disable GlobalProtect gateway if not immediately patchable.',
        actions: [
          'Disable GlobalProtect gateway if possible',
          'Implement strict IP allowlisting for GlobalProtect access',
          'Enable Threat Prevention signatures',
          'Isolate affected firewalls from critical systems',
          'Enable all available logging'
        ],
        priority: 'critical',
        timeframe: 'Within 1 hour'
      },
      postPatch: {
        title: 'Post-Patch Actions',
        description: 'Comprehensive security validation and hardening required.',
        actions: [
          'Perform full forensic analysis of affected systems',
          'Check for persistence mechanisms (cron jobs, backdoors)',
          'Review and rotate all credentials',
          'Examine configuration for unauthorized changes',
          'Reset device to known-good configuration if compromise suspected',
          'Update all GlobalProtect client software',
          'Re-baseline network traffic patterns'
        ],
        priority: 'critical',
        timeframe: 'Within 48 hours'
      },
      detection: {
        title: 'Detection & Monitoring',
        description: 'Critical - check for active compromise.',
        iocs: [
          'Files in /var/appweb/sslvpndocs/global-protect/portal/images/',
          'Unexpected Python processes',
          'Outbound connections to known C2 infrastructure',
          'Modifications to /etc/crontab or scheduled tasks',
          'New administrative users or SSH keys'
        ],
        priority: 'critical'
      }
    },
    'CVE-2023-27997': {
      emergencyPatching: {
        title: 'Emergency Patching',
        description: 'Update to latest FortiOS/FortiProxy version immediately.',
        patches: [
          'FortiOS 7.2.5 or later',
          'FortiOS 7.0.12 or later',
          'FortiOS 6.4.13 or later',
          'FortiProxy 7.2.4 or later',
          'FortiProxy 7.0.11 or later'
        ],
        priority: 'critical',
        timeframe: 'Immediate (within 24 hours)'
      },
      immediateAction: {
        title: 'Immediate Action',
        description: 'Disable SSL VPN if patching cannot be performed immediately.',
        actions: [
          'Disable SSL VPN portal if not critical',
          'Restrict SSL VPN access by source IP',
          'Enable IPS signatures for CVE-2023-27997',
          'Implement additional network segmentation',
          'Increase SSL VPN logging verbosity'
        ],
        priority: 'critical',
        timeframe: 'Within 4 hours'
      },
      postPatch: {
        title: 'Post-Patch Actions',
        description: 'Validate security posture and check for compromise.',
        actions: [
          'Reset all SSL VPN user passwords',
          'Review SSL VPN access logs for anomalies',
          'Check for unauthorized administrator accounts',
          'Examine system files for modifications',
          'Verify firewall policy configurations',
          'Update SSL VPN client software',
          'Re-issue VPN certificates if compromise suspected'
        ],
        priority: 'high',
        timeframe: 'Within 72 hours'
      },
      detection: {
        title: 'Detection & Monitoring',
        description: 'Monitor for signs of exploitation and persistence.',
        iocs: [
          'Unusual SSL VPN traffic patterns',
          'Unexpected system file modifications',
          'New user accounts or privilege escalations',
          'Suspicious outbound network connections',
          'Abnormal CPU or memory usage by SSL VPN processes'
        ],
        priority: 'high'
      }
    }
  };

  // Default mitigation template
  const defaultMitigation = {
    emergencyPatching: {
      title: 'Apply Security Updates',
      description: 'Apply vendor-provided patches or updates as soon as possible.',
      patches: ['Check vendor advisory for specific patch versions'],
      priority: 'high',
      timeframe: 'Per vendor guidance'
    },
    immediateAction: {
      title: 'Implement Workarounds',
      description: 'Apply temporary mitigations if patches are not immediately available.',
      actions: [
        'Review vendor advisory for workarounds',
        'Restrict network access to affected systems',
        'Enable additional monitoring and logging',
        'Implement defense-in-depth controls'
      ],
      priority: 'high',
      timeframe: 'Within 24 hours'
    },
    postPatch: {
      title: 'Post-Remediation',
      description: 'Verify patch effectiveness and security posture.',
      actions: [
        'Verify patch installation',
        'Test system functionality',
        'Review logs for exploitation attempts',
        'Update security documentation'
      ],
      priority: 'medium',
      timeframe: 'Within 1 week'
    },
    detection: {
      title: 'Detection & Monitoring',
      description: 'Monitor for signs of exploitation.',
      iocs: ['Check vendor and security advisories for specific indicators'],
      priority: 'medium'
    }
  };

  return mitigations[cve.cveId] || defaultMitigation;
}

// Map threats to potential CVEs based on tags, indicators, and context
export function mapThreatToCVEs(threat) {
  const cves = [];
  const tags = (threat.tags || []).map(t => t.toLowerCase());
  const indicator = (threat.indicator || '').toLowerCase();
  const name = (threat.name || '').toLowerCase();

  // Check for specific CVE mentions in threat data
  const cvePattern = /CVE-\d{4}-\d{4,}/gi;
  const matches = [...(threat.name || '').matchAll(cvePattern), ...(threat.description || '').matchAll(cvePattern)];

  matches.forEach(match => {
    const cveId = match[0];
    if (SAMPLE_KEVS[cveId]) {
      cves.push(SAMPLE_KEVS[cveId]);
    }
  });

  // Map based on product/vendor tags
  if (tags.includes('citrix') || name.includes('netscaler') || indicator.includes('netscaler')) {
    if (SAMPLE_KEVS['CVE-2023-4966'] && !cves.some(c => c.cveId === 'CVE-2023-4966')) {
      cves.push(SAMPLE_KEVS['CVE-2023-4966']);
    }
  }

  if (tags.includes('palo alto') || tags.includes('pan-os') || name.includes('globalprotect')) {
    if (SAMPLE_KEVS['CVE-2024-3400'] && !cves.some(c => c.cveId === 'CVE-2024-3400')) {
      cves.push(SAMPLE_KEVS['CVE-2024-3400']);
    }
  }

  if (tags.includes('fortinet') || tags.includes('fortigate') || name.includes('fortios')) {
    if (SAMPLE_KEVS['CVE-2023-27997'] && !cves.some(c => c.cveId === 'CVE-2023-27997')) {
      cves.push(SAMPLE_KEVS['CVE-2023-27997']);
    }
  }

  // Add general exploitation patterns
  if (tags.includes('exploit') || tags.includes('vulnerability') || tags.includes('cve')) {
    // Could add more generic CVEs here
  }

  return cves;
}

// Get CVE severity color
export function getCVESeverityColor(cvss) {
  if (cvss >= 9.0) return { bg: 'bg-red-500/20', text: 'text-red-400', border: 'border-red-500/30', label: 'CRITICAL' };
  if (cvss >= 7.0) return { bg: 'bg-orange-500/20', text: 'text-orange-400', border: 'border-orange-500/30', label: 'HIGH' };
  if (cvss >= 4.0) return { bg: 'bg-yellow-500/20', text: 'text-yellow-400', border: 'border-yellow-500/30', label: 'MEDIUM' };
  return { bg: 'bg-blue-500/20', text: 'text-blue-400', border: 'border-blue-500/30', label: 'LOW' };
}

// Map CVE to MITRE ATT&CK techniques
export function mapCVEToMitre(cve) {
  const techniques = [];
  const vulnName = (cve.vulnerabilityName || '').toLowerCase();
  const description = (cve.shortDescription || '').toLowerCase();
  const vendor = (cve.vendorProject || '').toLowerCase();
  const product = (cve.product || '').toLowerCase();

  // Import MITRE techniques for reference
  const T1190 = { id: 'T1190', name: 'Exploit Public-Facing Application', tactic: 'initialAccess', description: 'Exploit vulnerabilities in public apps' };
  const T1059 = { id: 'T1059', name: 'Command and Scripting Interpreter', tactic: 'execution', description: 'Execute commands via interpreters' };
  const T1203 = { id: 'T1203', name: 'Exploitation for Client Execution', tactic: 'execution', description: 'Exploit software vulnerabilities' };
  const T1068 = { id: 'T1068', name: 'Exploitation for Privilege Escalation', tactic: 'privilegeEscalation', description: 'Exploit vulnerabilities to escalate privileges' };
  const T1133 = { id: 'T1133', name: 'External Remote Services', tactic: 'initialAccess', description: 'Use external remote services' };
  const T1210 = { id: 'T1210', name: 'Exploitation of Remote Services', tactic: 'lateralMovement', description: 'Exploit remote services' };
  const T1078 = { id: 'T1078', name: 'Valid Accounts', tactic: 'initialAccess', description: 'Obtain and abuse credentials' };
  const T1486 = { id: 'T1486', name: 'Data Encrypted for Impact', tactic: 'impact', description: 'Encrypt data (ransomware)' };
  const T1027 = { id: 'T1027', name: 'Obfuscated Files or Information', tactic: 'defenseEvasion', description: 'Obfuscate malicious code' };

  // Remote Code Execution (RCE)
  if (vulnName.includes('remote code execution') || vulnName.includes('rce') || description.includes('remote code')) {
    techniques.push(T1190);
    techniques.push(T1203);
    techniques.push(T1059);
  }

  // Command Injection
  if (vulnName.includes('command injection') || description.includes('command injection')) {
    techniques.push(T1059);
    techniques.push(T1190);
  }

  // Privilege Escalation
  if (vulnName.includes('privilege escalation') || description.includes('escalate') || description.includes('elevated')) {
    techniques.push(T1068);
  }

  // Authentication Bypass
  if (vulnName.includes('authentication bypass') || vulnName.includes('auth bypass') || description.includes('bypass authentication')) {
    techniques.push(T1078);
    techniques.push(T1190);
  }

  // VPN/Remote Access vulnerabilities
  if (product.includes('vpn') || product.includes('gateway') || product.includes('remote access') ||
      vendor.includes('fortinet') || vendor.includes('palo alto') || vendor.includes('citrix')) {
    techniques.push(T1133);
    techniques.push(T1190);
  }

  // Buffer Overflow
  if (vulnName.includes('buffer overflow') || description.includes('buffer overflow')) {
    techniques.push(T1203);
    techniques.push(T1068);
  }

  // SQL Injection
  if (vulnName.includes('sql injection') || description.includes('sql injection')) {
    techniques.push(T1190);
  }

  // Lateral Movement capabilities
  if (description.includes('lateral movement') || description.includes('pivot')) {
    techniques.push(T1210);
  }

  // Ransomware-related
  if (cve.knownRansomwareCampaignUse === 'Known') {
    techniques.push(T1486);
    techniques.push(T1027);
  }

  // Default for any public-facing vulnerability
  if (techniques.length === 0) {
    techniques.push(T1190);
  }

  // Get unique techniques
  return [...new Map(techniques.map(t => [t.id, t])).values()];
}

// Format CVSS score with visual representation
export function formatCVSS(cvss) {
  const severity = getCVESeverityColor(cvss);
  return {
    score: cvss.toFixed(1),
    severity: severity.label,
    ...severity
  };
}

// Get external CVE links
export function getCVELinks(cveId) {
  return {
    nvd: `https://nvd.nist.gov/vuln/detail/${cveId}`,
    mitre: `https://cve.mitre.org/cgi-bin/cvename.cgi?name=${cveId}`,
    cisa: `https://www.cisa.gov/known-exploited-vulnerabilities-catalog`,
    github: `https://github.com/advisories?query=${cveId}`,
    exploitdb: `https://www.exploit-db.com/search?cve=${cveId}`
  };
}

// Check if CVE is in CISA KEV catalog
export function isKnownExploited(cveId) {
  return SAMPLE_KEVS[cveId]?.exploited || false;
}

// Get trending/priority status
export function getCVEPriority(cve) {
  const priorities = [];

  if (cve.exploited) {
    priorities.push({ label: 'ACTIVELY EXPLOITED', color: 'red', icon: '🚨' });
  }

  if (cve.trending) {
    priorities.push({ label: 'TRENDING', color: 'orange', icon: '📈' });
  }

  if (cve.knownRansomwareCampaignUse === 'Known') {
    priorities.push({ label: 'RANSOMWARE', color: 'purple', icon: '🔒' });
  }

  if (cve.cvss >= 9.0) {
    priorities.push({ label: 'CRITICAL CVSS', color: 'red', icon: '⚠️' });
  }

  return priorities;
}
