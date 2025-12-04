# 🛡️ SENTINEL - Threat Intelligence Platform

A production-ready, security-hardened threat intelligence dashboard for Vercel.

![SENTINEL Dashboard](https://img.shields.io/badge/Status-Production%20Ready-brightgreen)
![Vercel](https://img.shields.io/badge/Vercel-Hobby%20Compatible-blue)
![License](https://img.shields.io/badge/License-MIT-yellow)

## ✨ Features

- **Real-time Threat Feed** - Live data from URLhaus, ThreatFox, AbuseIPDB, OTX, VirusTotal, Shodan
- **Unified Search** - Query IPs, domains, and hashes across all feeds simultaneously
- **Security Hardened** - Input validation, rate limiting, optional API auth
- **Single Function** - Optimized for Vercel Hobby tier (1 serverless function)

## 📁 Project Structure

```
sentinel-threat-intel/
├── api/
│   └── index.js        # Single serverless function (all API routes)
├── src/
│   ├── App.jsx         # React dashboard
│   └── index.js        # Entry point
├── public/
│   └── index.html      # HTML template
├── package.json
├── vercel.json         # Vercel configuration
└── README.md
```

## 🚀 Deploy to Vercel

### Step 1: Create Repository

```bash
# Clone or download this project
git init
git add .
git commit -m "Initial commit"

# Push to GitHub
git remote add origin https://github.com/YOUR_USERNAME/sentinel-threat-intel.git
git push -u origin main
```

### Step 2: Deploy to Vercel

1. Go to [vercel.com/new](https://vercel.com/new)
2. Import your GitHub repository
3. Click **Deploy**

### Step 3: Add API Keys

In Vercel Dashboard → **Settings** → **Environment Variables**, add:

| Variable | Get Free Key |
|----------|-------------|
| `ABUSEIPDB_API_KEY` | [abuseipdb.com/register](https://www.abuseipdb.com/register) |
| `OTX_API_KEY` | [otx.alienvault.com](https://otx.alienvault.com/) |
| `VIRUSTOTAL_API_KEY` | [virustotal.com/gui/join-us](https://www.virustotal.com/gui/join-us) |
| `SHODAN_API_KEY` | [account.shodan.io/register](https://account.shodan.io/register) |

### Step 4: Redeploy

Go to **Deployments** → Click **⋮** on latest → **Redeploy**

## 🔒 Security Features

| Feature | Description |
|---------|-------------|
| Input Validation | Strict regex for IPs, domains, hashes |
| Rate Limiting | 60 requests/minute per IP |
| API Authentication | Optional `DASHBOARD_API_KEY` env var |
| Security Headers | X-Frame-Options, CSP, XSS Protection |
| Safe Errors | Internal errors never exposed |

### Enable API Authentication (Optional)

Add to Vercel Environment Variables:

```
DASHBOARD_API_KEY=your-secret-key-min-32-chars
ALLOWED_ORIGINS=https://yourdomain.com
```

## 📡 API Endpoints

All routes use a single function with query parameters:

```
GET  /api?endpoint=health     # Health check
GET  /api?endpoint=feeds      # Feed status
GET  /api?endpoint=threats    # Aggregated threats
POST /api?endpoint=search     # Unified IOC search
```

## 🆓 Free Tier Limits

| Feed | Limit | API Key Required |
|------|-------|------------------|
| URLhaus | Unlimited | ❌ No |
| ThreatFox | Unlimited | ❌ No |
| AbuseIPDB | 1,000/day | ✅ Yes |
| AlienVault OTX | Unlimited | ✅ Yes |
| VirusTotal | 500/day | ✅ Yes |
| Shodan | Limited | ✅ Yes |

**URLhaus and ThreatFox work immediately without any API keys!**

## 🛠️ Local Development

```bash
# Install dependencies
npm install

# Run development server
npm start

# Build for production
npm run build
```

## 📄 License

MIT License - feel free to use for personal or commercial projects.

---

Built with ❤️ for the cybersecurity community
