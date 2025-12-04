// MITRE ATT&CK Framework Mappings and Utilities

export const MITRE_TACTICS = {
  reconnaissance: { id: 'TA0043', name: 'Reconnaissance', description: 'Gather information for future operations' },
  resourceDevelopment: { id: 'TA0042', name: 'Resource Development', description: 'Establish resources to support operations' },
  initialAccess: { id: 'TA0001', name: 'Initial Access', description: 'Gain initial foothold within a network' },
  execution: { id: 'TA0002', name: 'Execution', description: 'Run malicious code' },
  persistence: { id: 'TA0003', name: 'Persistence', description: 'Maintain foothold in compromised systems' },
  privilegeEscalation: { id: 'TA0004', name: 'Privilege Escalation', description: 'Gain higher-level permissions' },
  defenseEvasion: { id: 'TA0005', name: 'Defense Evasion', description: 'Avoid detection' },
  credentialAccess: { id: 'TA0006', name: 'Credential Access', description: 'Steal account credentials' },
  discovery: { id: 'TA0007', name: 'Discovery', description: 'Explore the environment' },
  lateralMovement: { id: 'TA0008', name: 'Lateral Movement', description: 'Move through the environment' },
  collection: { id: 'TA0009', name: 'Collection', description: 'Gather data of interest' },
  commandAndControl: { id: 'TA0011', name: 'Command and Control', description: 'Communicate with compromised systems' },
  exfiltration: { id: 'TA0010', name: 'Exfiltration', description: 'Steal data' },
  impact: { id: 'TA0040', name: 'Impact', description: 'Manipulate, interrupt, or destroy systems and data' }
};

export const MITRE_TECHNIQUES = {
  // Command and Control
  T1071: { id: 'T1071', name: 'Application Layer Protocol', tactic: 'commandAndControl', description: 'Use application layer protocols for C2' },
  T1095: { id: 'T1095', name: 'Non-Application Layer Protocol', tactic: 'commandAndControl', description: 'Use non-application layer protocols for C2' },
  T1568: { id: 'T1568', name: 'Dynamic Resolution', tactic: 'commandAndControl', description: 'Dynamically establish C2 channel' },
  T1573: { id: 'T1573', name: 'Encrypted Channel', tactic: 'commandAndControl', description: 'Use encrypted communications' },

  // Initial Access
  T1566: { id: 'T1566', name: 'Phishing', tactic: 'initialAccess', description: 'Send phishing messages to gain access' },
  T1190: { id: 'T1190', name: 'Exploit Public-Facing Application', tactic: 'initialAccess', description: 'Exploit vulnerabilities in public apps' },
  T1133: { id: 'T1133', name: 'External Remote Services', tactic: 'initialAccess', description: 'Use external remote services' },
  T1189: { id: 'T1189', name: 'Drive-by Compromise', tactic: 'initialAccess', description: 'Compromise via malicious website' },

  // Execution
  T1059: { id: 'T1059', name: 'Command and Scripting Interpreter', tactic: 'execution', description: 'Execute commands via interpreters' },
  T1203: { id: 'T1203', name: 'Exploitation for Client Execution', tactic: 'execution', description: 'Exploit software vulnerabilities' },
  T1204: { id: 'T1204', name: 'User Execution', tactic: 'execution', description: 'Rely on user to execute malicious code' },

  // Persistence
  T1547: { id: 'T1547', name: 'Boot or Logon Autostart Execution', tactic: 'persistence', description: 'Execute at boot or logon' },
  T1543: { id: 'T1543', name: 'Create or Modify System Process', tactic: 'persistence', description: 'Create/modify system processes' },
  T1053: { id: 'T1053', name: 'Scheduled Task/Job', tactic: 'persistence', description: 'Schedule tasks for execution' },

  // Defense Evasion
  T1027: { id: 'T1027', name: 'Obfuscated Files or Information', tactic: 'defenseEvasion', description: 'Obfuscate malicious code' },
  T1070: { id: 'T1070', name: 'Indicator Removal', tactic: 'defenseEvasion', description: 'Remove evidence of compromise' },
  T1140: { id: 'T1140', name: 'Deobfuscate/Decode Files', tactic: 'defenseEvasion', description: 'Decode/deobfuscate payloads' },

  // Credential Access
  T1110: { id: 'T1110', name: 'Brute Force', tactic: 'credentialAccess', description: 'Guess passwords' },
  T1555: { id: 'T1555', name: 'Credentials from Password Stores', tactic: 'credentialAccess', description: 'Extract credentials from stores' },
  T1003: { id: 'T1003', name: 'OS Credential Dumping', tactic: 'credentialAccess', description: 'Dump credentials from OS' },

  // Impact
  T1486: { id: 'T1486', name: 'Data Encrypted for Impact', tactic: 'impact', description: 'Encrypt data (ransomware)' },
  T1499: { id: 'T1499', name: 'Endpoint Denial of Service', tactic: 'impact', description: 'Cause denial of service' },
  T1490: { id: 'T1490', name: 'Inhibit System Recovery', tactic: 'impact', description: 'Prevent system recovery' }
};

// Map threat types and tags to MITRE ATT&CK techniques
export function mapThreatToMitre(threat) {
  const techniques = [];
  const type = threat.type?.toLowerCase() || '';
  const tags = threat.tags?.map(t => t.toLowerCase()) || [];

  // Malware URLs and Payload Delivery
  if (type.includes('malware') || type.includes('url') || tags.includes('malware') || tags.includes('payload')) {
    techniques.push(MITRE_TECHNIQUES.T1189); // Drive-by Compromise
    techniques.push(MITRE_TECHNIQUES.T1204); // User Execution
    techniques.push(MITRE_TECHNIQUES.T1071); // Application Layer Protocol
  }

  // Malicious IPs
  if (type.includes('ip') || type.includes('malicious ip')) {
    techniques.push(MITRE_TECHNIQUES.T1071); // Application Layer Protocol
    techniques.push(MITRE_TECHNIQUES.T1095); // Non-Application Layer Protocol
    techniques.push(MITRE_TECHNIQUES.T1190); // Exploit Public-Facing Application
  }

  // Botnet C2
  if (type.includes('botnet') || type.includes('c2') || type.includes('command') || tags.includes('botnet_cc')) {
    techniques.push(MITRE_TECHNIQUES.T1071); // Application Layer Protocol
    techniques.push(MITRE_TECHNIQUES.T1095); // Non-Application Layer Protocol
    techniques.push(MITRE_TECHNIQUES.T1568); // Dynamic Resolution
    techniques.push(MITRE_TECHNIQUES.T1573); // Encrypted Channel
  }

  // Phishing
  if (tags.includes('phishing') || type.includes('phishing')) {
    techniques.push(MITRE_TECHNIQUES.T1566); // Phishing
    techniques.push(MITRE_TECHNIQUES.T1204); // User Execution
  }

  // Ransomware
  if (tags.includes('ransomware') || type.includes('ransomware')) {
    techniques.push(MITRE_TECHNIQUES.T1486); // Data Encrypted for Impact
    techniques.push(MITRE_TECHNIQUES.T1490); // Inhibit System Recovery
    techniques.push(MITRE_TECHNIQUES.T1070); // Indicator Removal
  }

  // Trojan/Backdoor
  if (tags.includes('trojan') || tags.includes('backdoor') || type.includes('trojan')) {
    techniques.push(MITRE_TECHNIQUES.T1071); // Application Layer Protocol
    techniques.push(MITRE_TECHNIQUES.T1547); // Boot or Logon Autostart Execution
    techniques.push(MITRE_TECHNIQUES.T1543); // Create or Modify System Process
  }

  // Credential Theft
  if (tags.includes('stealer') || tags.includes('credential') || type.includes('credential')) {
    techniques.push(MITRE_TECHNIQUES.T1555); // Credentials from Password Stores
    techniques.push(MITRE_TECHNIQUES.T1003); // OS Credential Dumping
    techniques.push(MITRE_TECHNIQUES.T1110); // Brute Force
  }

  // Obfuscation/Evasion
  if (tags.includes('obfuscation') || tags.includes('evasion') || tags.includes('packed')) {
    techniques.push(MITRE_TECHNIQUES.T1027); // Obfuscated Files or Information
    techniques.push(MITRE_TECHNIQUES.T1140); // Deobfuscate/Decode Files
  }

  // Default for unknown threats
  if (techniques.length === 0) {
    techniques.push(MITRE_TECHNIQUES.T1071); // Application Layer Protocol
    techniques.push(MITRE_TECHNIQUES.T1190); // Exploit Public-Facing Application
  }

  // Get unique techniques
  return [...new Map(techniques.map(t => [t.id, t])).values()];
}

// Generate mitigation recommendations
export function generateMitigations(threat) {
  const mitigations = [];
  const type = threat.type?.toLowerCase() || '';
  const tags = (threat.tags || []).map(t => t.toLowerCase());

  // General mitigations
  mitigations.push({
    id: 'M1',
    category: 'Network Security',
    title: 'Block Indicator',
    description: `Block the indicator ${threat.indicator} at network perimeter (firewall, proxy, IDS/IPS)`,
    priority: 'high',
    tools: ['Firewall', 'IDS/IPS', 'Proxy', 'DNS Filtering']
  });

  // URL-specific mitigations
  if (type.includes('url') || type.includes('malware')) {
    mitigations.push({
      id: 'M2',
      category: 'Email Security',
      title: 'Email Filtering',
      description: 'Configure email gateway to block URLs matching this pattern and similar domains',
      priority: 'high',
      tools: ['Email Gateway', 'URL Filtering', 'Sandbox']
    });

    mitigations.push({
      id: 'M3',
      category: 'Endpoint Security',
      title: 'Browser Protection',
      description: 'Enable browser security features and deploy web filtering solutions',
      priority: 'medium',
      tools: ['Web Filter', 'Browser Isolation', 'Safe Browsing']
    });
  }

  // IP-specific mitigations
  if (type.includes('ip')) {
    mitigations.push({
      id: 'M4',
      category: 'Network Security',
      title: 'IP Reputation Blocking',
      description: 'Add IP to blocklist and configure reputation-based blocking',
      priority: 'high',
      tools: ['Firewall', 'IPS', 'Threat Intelligence Platform']
    });

    mitigations.push({
      id: 'M5',
      category: 'Monitoring',
      title: 'Traffic Analysis',
      description: 'Monitor for any existing connections to this IP and investigate affected systems',
      priority: 'critical',
      tools: ['SIEM', 'NetFlow', 'EDR']
    });
  }

  // Botnet-specific mitigations
  if (type.includes('botnet') || tags.includes('botnet_cc')) {
    mitigations.push({
      id: 'M6',
      category: 'Incident Response',
      title: 'Identify Infected Hosts',
      description: 'Search for systems communicating with this C2 server and isolate them',
      priority: 'critical',
      tools: ['SIEM', 'EDR', 'Network Monitoring']
    });
  }

  // Ransomware mitigations
  if (tags.includes('ransomware')) {
    mitigations.push({
      id: 'M7',
      category: 'Backup & Recovery',
      title: 'Verify Backups',
      description: 'Ensure backup systems are isolated and verify backup integrity',
      priority: 'critical',
      tools: ['Backup Solution', 'Snapshot Management']
    });
  }

  // User awareness
  mitigations.push({
    id: 'M8',
    category: 'User Training',
    title: 'Security Awareness',
    description: 'Notify users about this threat and provide indicators to watch for',
    priority: 'medium',
    tools: ['Security Awareness Training', 'Phishing Simulation']
  });

  return mitigations;
}

// Generate remediation playbook
export function generateRemediation(threat) {
  const steps = [];
  const severity = threat.severity || 'medium';

  // Immediate response steps
  steps.push({
    phase: 'Detection & Analysis',
    order: 1,
    title: 'Confirm Threat Presence',
    description: 'Search SIEM and EDR logs for any evidence of this indicator in your environment',
    commands: [
      `Search SIEM: index=* "${threat.indicator}"`,
      `Check firewall logs for connections to: ${threat.indicator}`,
      `Query EDR for indicator: ${threat.indicator}`
    ],
    estimatedTime: '15-30 minutes',
    role: 'SOC Analyst'
  });

  steps.push({
    phase: 'Detection & Analysis',
    order: 2,
    title: 'Assess Scope',
    description: 'Determine how many systems may be affected and timeline of activity',
    commands: [
      'Review connection logs for affected timeframe',
      'Identify all internal IPs that communicated with the indicator',
      'Check for lateral movement from identified systems'
    ],
    estimatedTime: '30-60 minutes',
    role: 'SOC Analyst'
  });

  // Containment
  steps.push({
    phase: 'Containment',
    order: 3,
    title: 'Block Indicator',
    description: 'Immediately block the indicator at all security control points',
    commands: [
      `Add ${threat.indicator} to firewall blocklist`,
      `Update IPS/IDS signatures`,
      `Configure DNS sinkhole if applicable`,
      `Push block to endpoint security solutions`
    ],
    estimatedTime: '15-30 minutes',
    role: 'Security Engineer'
  });

  if (severity === 'critical' || severity === 'high') {
    steps.push({
      phase: 'Containment',
      order: 4,
      title: 'Isolate Affected Systems',
      description: 'Network-isolate any systems found communicating with this indicator',
      commands: [
        'Identify affected systems from analysis',
        'Implement network isolation via firewall or NAC',
        'Disable network adapters if necessary',
        'Maintain system power for forensics'
      ],
      estimatedTime: '15-30 minutes',
      role: 'Incident Responder'
    });
  }

  // Eradication
  steps.push({
    phase: 'Eradication',
    order: 5,
    title: 'Remove Malicious Artifacts',
    description: 'Clean affected systems and remove any malicious files or persistence mechanisms',
    commands: [
      'Run full AV/EDR scan on affected systems',
      'Check for persistence mechanisms (scheduled tasks, registry keys, services)',
      'Remove malicious files and executables',
      'Reset compromised credentials'
    ],
    estimatedTime: '1-2 hours per system',
    role: 'Incident Responder'
  });

  // Recovery
  steps.push({
    phase: 'Recovery',
    order: 6,
    title: 'Restore Normal Operations',
    description: 'Verify systems are clean and restore to production',
    commands: [
      'Verify no malicious indicators remain',
      'Patch vulnerabilities that allowed compromise',
      'Update security policies and rules',
      'Monitor systems closely for 72 hours',
      'Restore network connectivity gradually'
    ],
    estimatedTime: '2-4 hours',
    role: 'Security Engineer'
  });

  // Post-incident
  steps.push({
    phase: 'Post-Incident',
    order: 7,
    title: 'Document and Learn',
    description: 'Document the incident and implement lessons learned',
    commands: [
      'Complete incident report with timeline',
      'Update detection rules based on TTPs observed',
      'Share IOCs with threat intel community',
      'Conduct post-incident review meeting',
      'Implement additional preventive controls if needed'
    ],
    estimatedTime: '2-4 hours',
    role: 'Incident Manager'
  });

  return {
    threat: threat.name,
    severity: threat.severity,
    estimatedTotalTime: severity === 'critical' ? '6-12 hours' : severity === 'high' ? '4-8 hours' : '2-6 hours',
    steps: steps,
    references: [
      'NIST SP 800-61 Rev. 2: Computer Security Incident Handling Guide',
      'SANS Incident Handler\'s Handbook',
      'Your organization\'s incident response plan'
    ]
  };
}

// Get MITRE ATT&CK navigator URL
export function getMitreNavigatorUrl() {
  return `https://mitre-attack.github.io/attack-navigator/`;
}

// Get MITRE ATT&CK technique URL
export function getMitreTechniqueUrl(techniqueId) {
  return `https://attack.mitre.org/techniques/${techniqueId}/`;
}
