# WebVAPT — Automated Web Application Security Assessment, Vulnerability Correlation & Reporting Framework

[![Python](https://img.shields.io/badge/Python-3.10%2B-blue.svg)](https://www.python.org/)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Framework](https://img.shields.io/badge/Security-VAPT%20Orchestrator-red.svg)]()

---

## 1. Project Motivation

In modern application security assessments, security engineers and penetration testers frequently run multiple disjoint security tools:
- **Nmap** for infrastructure and open port reconnaissance.
- **OWASP ZAP** for in-depth web application crawling and dynamic analysis (DAST).
- **Nuclei** for fast, template-driven vulnerability pattern matching.
- **Custom scripts** for security headers, SSL/TLS checks, and cookie posture analysis.

### The Problem
1. **Tool Fragmentation & Incompatible Formats:** Each engine speaks a different language. ZAP produces XML/JSON alerts, Nuclei emits JSONL, Nmap outputs raw text/XML, and custom scripts return ad-hoc outputs.
2. **Duplicate Findings (Alert Fatigue):** Multiple tools often catch the exact same misconfiguration (e.g. Missing `Content-Security-Policy` detected by both ZAP and custom checks). Security analysts waste hours filtering duplicates.
3. **Evidence Loss:** Generic aggregators frequently drop tool-specific proof-of-concept payloads, HTTP matchers, or parameter context.
4. **Disjointed Reporting:** Compiling findings into an executive-ready PDF report with severity matrices usually requires tedious manual documentation.

### The Solution: WebVAPT
**WebVAPT** is built as an end-to-end orchestration, normalization, correlation, and reporting pipeline. It does **not** seek to replace world-class scanners; instead, it brings them together under a unified schema, removes duplicates intelligently, preserves proof-of-concept evidence, calculates unified risk metrics, and generates publication-grade PDF and JSON reports.

---

## 2. Architecture & High-Level Workflow

WebVAPT executes as a deterministic, multi-phase assessment pipeline:

```
                  +-----------------------------------------+
                  |               Target URL                |
                  +--------------------+--------------------+
                                       |
                                       v
                  +-----------------------------------------+
                  |       1. Target & Policy Validation     |
                  |     (URL schema, Netloc, Allowlist)     |
                  +--------------------+--------------------+
                                       |
                                       v
                  +-----------------------------------------+
                  |       2. HTTP Reconnaissance Phase      |
                  | (Status, Headers, Server, Title, Trails)|
                  +--------------------+--------------------+
                                       |
         +-----------------------------+-----------------------------+
         |                             |                             |
         v                             v                             v
+------------------+          +------------------+          +------------------+
|  Custom Python   |          |  Network Recon   |          |  OWASP ZAP DAST  |
| Header & Cookie  |          |  (Nmap Service)  |          | (Spider/Passive/ |
|     Analyzer     |          |                  |          |     Active)      |
+--------+---------+          +--------+---------+          +--------+---------+
         |                             |                             |
         +-----------------------------+-----------------------------+
                                       |
                                       v
                              +------------------+
                              | Nuclei Templates |
                              |  Pattern Engine  |
                              +--------+---------+
                                       |
                                       v
                  +-----------------------------------------+
                  |        3. Finding Normalization         |
                  |  (Unified Schema & Deterministic IDs)   |
                  +--------------------+--------------------+
                                       |
                                       v
                  +-----------------------------------------+
                  |      4. Correlation & Deduplication     |
                  | (Title + CWE + Endpoint + Parameter key)|
                  +--------------------+--------------------+
                                       |
                                       v
                  +-----------------------------------------+
                  |        5. Risk Metric Processing        |
                  | (Severity Distribution & Impact Ranking)|
                  +--------------------+--------------------+
                                       |
         +-----------------------------+-----------------------------+
         |                                                           |
         v                                                           v
+------------------+                                        +------------------+
| Normalized JSON  |                                        | Executive PDF    |
| results/normal.. |                                        | reports/VAPT_... |
+------------------+                                        +------------------+
```

---

## 3. In-Depth Module Breakdown

### 3.1 `scanner.py` — The Master Orchestrator
The central CLI entry point coordinating the complete assessment lifecycle.
- **Safety Enforcement:** Validates the target URL, checks configured allowlists, and enforces confirmation (`--confirm`) prior to initiating active scans.
- **Isolated Execution:** Executes engines inside protected blocks. If an external tool (such as Nmap or ZAP) is offline or times out, it logs the error without aborting the other scanners.
- **Timing & Metrics:** Tracks wall-clock execution duration for each phase and prints real-time status output.

### 3.2 `config.py` — Central Configuration
Implements centralized configuration management with environment-variable overrides:
- Eliminates hardcoded credentials and secrets.
- Manages scan timeouts: `VAPT_HTTP_TIMEOUT`, `VAPT_NMAP_TIMEOUT`, `VAPT_NUCLEI_TIMEOUT`, `VAPT_ZAP_SPIDER_TIMEOUT`, and `VAPT_ZAP_SCAN_TIMEOUT`.
- Configures ZAP connection parameters (`VAPT_ZAP_HOST`, `VAPT_ZAP_PORT`, `VAPT_ZAP_API_KEY`).
- Manages output directory paths (`results/raw/`, `results/normalized/`, `reports/`, `evidence/`).

### 3.3 `modules/target.py` — Target & Scope Validation
- Ensures URLs strictly adhere to standard `http` or `https` schemes via `urllib.parse.urlparse`.
- Validates the network location (`netloc`) to protect against malformed inputs and path-traversal style input attacks.

### 3.4 `modules/recon.py` — Passive HTTP Reconnaissance
- Probes the target using `requests` with automated redirect tracking (`allow_redirects=True`).
- Records HTTP response status code, Server banner, Content-Type, cookies, and page title (via BeautifulSoup).
- Identifies cross-domain redirect traps to ensure scanning scope does not leak to unintended third-party hosts.

### 3.5 `modules/custom_checks.py` — Native Python Security Engines
Lightweight, native Python vulnerability checks requiring zero external binaries:
- **Security Header Analysis:** Evaluates presence and configuration of `Content-Security-Policy`, `Strict-Transport-Security`, `X-Content-Type-Options`, and `X-Frame-Options`.
- **Information Disclosure Detection:** Identifies technology fingerprint leakage in response headers (`X-Powered-By`, `X-AspNet-Version`, version-rich `Server` strings).
- **Cookie Security Analyzer:** Audits session cookie flags:
  - `Secure`: Flags cookies sent over unencrypted channels.
  - `HttpOnly`: Mitigates client-side session theft via XSS.
  - `SameSite`: Identifies missing CSRF mitigation postures.

### 3.6 `modules/nmap_scan.py` — Port & Service Scanner
- Spawns Nmap safely using argument arrays (`subprocess.run(["nmap", "-sV", host])`) to eliminate shell command injection risks.
- Employs regex parsers to structure port states, protocols, services, and version banners into actionable data.
- Persists raw command stdout/stderr to `results/raw/nmap_raw.json`.

### 3.7 `modules/zap_scan.py` — OWASP ZAP API Engine
- Communicates directly with the OWASP ZAP REST API without requiring heavy third-party SDK dependencies.
- **Daemon Health Check:** Queries `/JSON/core/view/version/` to verify connectivity before initiating scans.
- **Spider Controller:** Triggers and monitors ZAP's URL spider until completion or timeout.
- **Passive vs Active Scanning:**
  - *Passive Scan (Default):* Analyzes spidered traffic without sending intrusive payloads.
  - *Active Scan (Opt-in):* Intrusive vulnerability scanning triggered exclusively when `--zap-active` and `--confirm` are specified.
- Extracts structured vulnerability alerts with risk codes, confidence levels, CWE IDs, parameters, and evidence.
- Persists raw alerts to `results/raw/zap_raw.json`.

### 3.8 `modules/nuclei_scan.py` — Template-Based Scanner
- Executes ProjectDiscovery Nuclei using `-jsonl` and `-silent` flags.
- Parses line-by-line JSON streams to extract template IDs, severity, matcher names, CWE classifications, and CVE references.
- Persists raw outputs to `results/raw/nuclei_raw.json`.

### 3.9 `modules/normalizer.py` — Common Finding Model
Standardizes disparate tool outputs into a unified schema:

```json
{
  "id": "e4f8b910123a",
  "title": "Missing Content-Security-Policy header",
  "severity": "Medium",
  "confidence": "High",
  "endpoint": "http://demo.testfire.net/",
  "method": "GET",
  "parameter": "",
  "description": "The response does not set the Content-Security-Policy header.",
  "impact": "Exposes application to cross-site scripting (XSS) and injection attacks.",
  "remediation": "Implement a strict Content-Security-Policy header.",
  "evidence": "",
  "tool": "Custom Security Header Analyzer",
  "sources": ["Custom Security Header Analyzer", "ZAP"],
  "references": "https://owasp.org/...",
  "owasp": "A05 - Security Misconfiguration",
  "cwe": "CWE-693",
  "cve": "",
  "cvss": null,
  "status": "Confirmed"
}
```
- **Deterministic IDs:** Uses SHA-256 hashes derived from `tool:title:endpoint`.
- **Honest Metadata:** Missing CVE or CVSS attributes remain empty or `null`—never fabricated.

### 3.10 `modules/deduplicator.py` — Finding Correlation
- **Composite Key Matching:** Uses a composite key: `normalized_title | cwe | endpoint | parameter`.
- **Source Attribution:** When multiple engines detect the same issue, all detection tools are recorded in `sources: ["ZAP", "Custom Checks"]`.
- **Risk Preservation:** Retains the highest severity rating among reporting engines.
- **Evidence Accumulation:** Combines evidence strings across tools without overwriting proof-of-concept details.

### 3.11 `modules/risk.py` — Severity Metrics
- Standardizes severities: `Informational`, `Low`, `Medium`, `High`, `Critical`.
- Generates metric distributions for executive-level dashboards.

### 3.12 `report_generator.py` — Professional PDF Report Engine
Generates publication-quality PDF assessment reports via ReportLab:
- **Cover Page:** Clean title layout, scope target, date, and engines used.
- **Executive Summary:** Overview of posture and findings distribution.
- **Severity Matrix:** Structured table styled with industry-standard risk colors.
- **Scope & Reconnaissance Details:** Target host, status codes, server technologies, and page titles.
- **Detailed Findings:** Individual vulnerability cards with metadata tables, descriptions, evidence, remediation, and references.
- **Sanitization & Safety:** Escapes untrusted XML/HTML characters (`<`, `>`, `&`) to prevent PDF generation crashes from raw exploit payloads.
- **Disclaimers:** Formal statements regarding false positives, scope boundaries, and the necessity of manual verification.

---

## 4. Installation & Setup

### Prerequisites
- **Python:** 3.10 or higher
- **macOS / Linux / Windows WSL**

### 1. Clone the Repository
```bash
git clone https://github.com/kusumkumar1729/WebVAPT.git
cd WebVAPT/vapt-framework
```

### 2. Set Up Virtual Environment & Dependencies
```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

*(Installed libraries: `requests`, `beautifulsoup4`, `reportlab`, `pytest`)*

### 3. Optional External Tools Setup
The framework runs gracefully even without external tools. To enable full engine capabilities:

- **Nmap:**
  ```bash
  # macOS
  brew install nmap
  # Debian/Ubuntu
  sudo apt-get install nmap
  ```
- **Nuclei:**
  ```bash
  go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
  ```
- **OWASP ZAP:**
  - Launch OWASP ZAP (GUI or headless).
  - Ensure API is enabled on port `8080`.
  - In ZAP Options $\rightarrow$ API: Check **Disable API key** (or set `export VAPT_ZAP_API_KEY="your-key"`).

---

## 5. Usage & CLI Examples

### Fast Scan (Native Python Checks & Reconnaissance Only)
```bash
python scanner.py --target http://demo.testfire.net/ --skip-nmap --skip-nuclei --skip-zap
```

### Full Standard Assessment (All Available Tools, Safe Passive Mode)
```bash
python scanner.py --target http://demo.testfire.net/
```

### Active Penetration Test (Intrusive Testing Opt-in)
```bash
python scanner.py --target http://demo.testfire.net/ --zap-active --confirm
```

### Selective Engine Execution
```bash
# Skip Nmap and Nuclei, focus on ZAP and Custom Checks
python scanner.py --target http://demo.testfire.net/ --skip-nmap --skip-nuclei
```

---

## 6. Configuration Environment Variables

| Variable | Default | Purpose |
|---|---|---|
| `VAPT_ALLOWLIST` | `""` | Comma-delimited list of permitted domains for scan authorization |
| `VAPT_HTTP_TIMEOUT` | `15` | Timeout (seconds) for HTTP reconnaissance |
| `VAPT_NMAP_TIMEOUT` | `120` | Timeout (seconds) for Nmap scans |
| `VAPT_NUCLEI_TIMEOUT` | `300` | Timeout (seconds) for Nuclei scans |
| `VAPT_ZAP_HOST` | `127.0.0.1` | OWASP ZAP API daemon host |
| `VAPT_ZAP_PORT` | `8080` | OWASP ZAP API daemon port |
| `VAPT_ZAP_API_KEY` | `""` | OWASP ZAP API key |
| `VAPT_ZAP_SPIDER_TIMEOUT`| `120` | Timeout (seconds) for ZAP spidering |
| `VAPT_ZAP_SCAN_TIMEOUT`  | `600` | Timeout (seconds) for ZAP passive/active scans |
| `VAPT_RESULTS_DIR` | `results` | Output root directory |
| `VAPT_REPORTS_DIR` | `reports` | PDF reports storage directory |

---

## 7. Output Artifacts

Every completed assessment generates structured outputs:

- **Raw Engine Data:**
  - `results/raw/nmap_raw.json`
  - `results/raw/zap_raw.json`
  - `results/raw/nuclei_raw.json`
- **Normalized Findings (JSON):**
  - `results/normalized/findings_<YYYY-MM-DD>.json`
- **Executive Audit Report (PDF):**
  - `reports/VAPT_Report_<YYYY-MM-DD>.pdf`

---

## 8. Verification & Testing

WebVAPT includes a unit test suite covering validation, parsing, normalizers, deduplication, report generation, and error resilience.

Run tests using pytest:
```bash
python -m pytest tests/ -v
```

All tests execute against mock data—no live network requests or external tools required.

---

## 9. Limitations & Safety Guidelines

- **Authorization Requirement:** WebVAPT is intended strictly for authorized security assessments. Always obtain written authorization before scanning target systems.
- **Active Scanning Safeguards:** Active scanning is disabled by default and requires explicit CLI confirmation (`--zap-active --confirm`).
- **Contextual Verification:** Automated scanners may produce false positives; findings should be manually validated by a qualified security professional.
