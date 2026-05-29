# X-VERDIKT

**No More Tool-Hopping.**

Deep IOC enrichment across 11+ threat intelligence sources. Built for analysts who need more than a verdict — full reputation context, geolocation, network metadata, and privacy flags in a single view.

Live: [h3ad-sec.github.io/X-VERDIKT](https://h3ad-sec.github.io/X-VERDIKT/)

---

## Modes

### Standard Enrichment

Supports IPv4, IPv6, domains, URLs, and MD5 / SHA-1 / SHA-256 / SHA-512 hashes. Each IOC type is scored against a dedicated source set.

| Source | IP | Domain | URL | Hash |
|--------|----|--------|-----|------|
| VirusTotal | 30 pts | 50 pts | 50 pts | 25 pts |
| AbuseIPDB | 40 pts | — | — | — |
| OTX | 10 pts | 10 pts | 10 pts | 10 pts |
| ThreatFox | 20 pts | 20 pts | — | 10 pts |
| URLScan | — | 20 pts | 20 pts | — |
| URLhaus | — | — | 20 pts | — |
| MalwareBazaar | — | — | — | 10 pts |
| HybridAnalysis | — | — | — | 20 pts |
| FileScan.io | — | — | — | 25 pts |
| Shodan | supplementary | — | — | — |

Shodan provides ports, CVEs, and threat tags for IPs without contributing to the score.

---

### IP Intel Mode

Deep-dive mode for IP addresses only. Pulls geolocation, ASN, organization, domain, and privacy context alongside full threat reputation data.

**Sources:** IPLocate · AbuseIPDB · VirusTotal · OTX · ThreatFox

**Privacy flags:** TOR · VPN · PROXY · HOSTING · BOGON · ABUSER · ANON · iCLOUD

Results include a dedicated table with country, organization, domain, and all privacy flags per IP. Copy as KV (≤ 5 IPs) or TSV (bulk). Export to Excel.

---

## Features

- Parallel scan engine — all sources fire simultaneously
- Auto-detects and defangs obfuscated indicators (`hxxps://`, `1[.]2[.]3[.]4`, `[dot]`)
- Bulk textarea and file upload (.txt, .csv, .json, .xlsx)
- Quick single-IOC lookup bar
- Mode tabs: BULK / IP / IPv6 / DOMAIN+URL / HASH / IP INTEL
- Detail modal with per-source raw data
- Export: CSV, JSON, Markdown, Excel
- Dark / light theme
- Fully responsive — works on mobile, tablet, and desktop

---

## Stack

- Vanilla JS, HTML, CSS — no framework, no build step
- GitHub Pages (static frontend)
- Vercel serverless functions (all API calls proxied server-side — managed mode only)

---

## File structure

```
X-VERDIKT/
├── index.html
├── css/style.css
├── js/
│   ├── ioc-parser.js   — multi-type parser, defang support
│   ├── api.js          — 11 source integrations + response parsers
│   ├── scanner.js      — parallel scan engine (standard + IP Intel)
│   ├── ui.js           — table, modal, IP Intel rendering
│   ├── export.js       — CSV / JSON / Markdown / Excel
│   └── app.js          — init, server probe, file upload
└── api/                — Vercel serverless proxies
    ├── vt.js · abuseipdb.js · otx.js · urlscan.js · threatfox.js
    ├── urlhaus.js · malwarebazaar.js · hybridanalysis.js
    ├── shodan.js · filescan.js · iplocate.js · status.js
```

---

## Part of H3AD-SEC

X-VERDIKT is a sub-tool under [H3AD-X](https://h3ad-sec.github.io/H3AD-X/) — Threat Intelligence hub of the [H3AD-SEC](https://h3ad-sec.github.io) platform.

Related tools: [VERDIKT](https://h3ad-sec.github.io/VERDIKT/) · [PARSE-X](https://h3ad-sec.github.io/PARSE-X/)


## H3AD-SEC Platform Modules

| Module | Tools |
|--------|-------|
| [H3AD-X](https://h3ad-sec.github.io/H3AD-X/) | X-VERDIKT, PARSE-X, DNSCOPE |
| [H3AD-AI](https://h3ad-sec.github.io/H3AD-AI/) | INSIGHT-AI, QUERYCRAFT-AI, FPLENS-AI, ATTMAP-AI, CHRONO-AI, MALBRIEF-AI |
| [H3AD-DETECT](https://h3ad-sec.github.io/H3AD-DETECT/) | TRACERULES |
| [H3AD-HUNT](https://h3ad-sec.github.io/H3AD-HUNT/) | HYPOS, PIVEX, TRACEPULSE |
| [H3AD-OPS](https://h3ad-sec.github.io/H3AD-OPS/) | QUICKTRACE, SHIFTLOG, PHISHOPS |
| [H3AD-DF](https://h3ad-sec.github.io/H3AD-DF/) | REGSCOPE |
| [H3AD-IR](https://h3ad-sec.github.io/H3AD-IR/) | — |
