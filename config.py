"""Centralized configuration — reads from environment variables with sensible defaults."""
import os

# ── Target ──────────────────────────────────────────────────────────────
TARGET_ALLOWLIST = [t.strip() for t in os.getenv("VAPT_ALLOWLIST", "").split(",") if t.strip()]

# ── Timeouts (seconds) ─────────────────────────────────────────────────
HTTP_TIMEOUT = int(os.getenv("VAPT_HTTP_TIMEOUT", "15"))
NMAP_TIMEOUT = int(os.getenv("VAPT_NMAP_TIMEOUT", "120"))
NUCLEI_TIMEOUT = int(os.getenv("VAPT_NUCLEI_TIMEOUT", "300"))
ZAP_SPIDER_TIMEOUT = int(os.getenv("VAPT_ZAP_SPIDER_TIMEOUT", "120"))
ZAP_SCAN_TIMEOUT = int(os.getenv("VAPT_ZAP_SCAN_TIMEOUT", "600"))

# ── ZAP ─────────────────────────────────────────────────────────────────
ZAP_HOST = os.getenv("VAPT_ZAP_HOST", "127.0.0.1")
ZAP_PORT = int(os.getenv("VAPT_ZAP_PORT", "8080"))
ZAP_API_KEY = os.getenv("VAPT_ZAP_API_KEY", "")
ZAP_BASE_URL = f"http://{ZAP_HOST}:{ZAP_PORT}"

# ── Output paths ────────────────────────────────────────────────────────
RESULTS_DIR = os.getenv("VAPT_RESULTS_DIR", "results")
RAW_DIR = os.path.join(RESULTS_DIR, "raw")
NORMALIZED_DIR = os.path.join(RESULTS_DIR, "normalized")
REPORTS_DIR = os.getenv("VAPT_REPORTS_DIR", "reports")
EVIDENCE_DIR = os.getenv("VAPT_EVIDENCE_DIR", "evidence")

# ── Nuclei ──────────────────────────────────────────────────────────────
NUCLEI_EXTRA_ARGS = [a for a in os.getenv("VAPT_NUCLEI_ARGS", "").split() if a]
