"""Comprehensive test suite for WebVAPT framework.

Tests use mocked data only — no intrusive scans or real targets.
"""
import json
import os
import sys
import tempfile
import unittest
from unittest.mock import patch, MagicMock

# Ensure project root is on path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


class TestTargetValidation(unittest.TestCase):
    def test_valid_http(self):
        from modules.target import validate_target
        self.assertEqual(validate_target("http://example.com"), "http://example.com")

    def test_valid_https(self):
        from modules.target import validate_target
        self.assertEqual(validate_target("https://example.com/app"), "https://example.com/app")

    def test_invalid_scheme(self):
        from modules.target import validate_target
        with self.assertRaises(ValueError):
            validate_target("ftp://example.com")

    def test_missing_netloc(self):
        from modules.target import validate_target
        with self.assertRaises(ValueError):
            validate_target("http://")

    def test_no_scheme(self):
        from modules.target import validate_target
        with self.assertRaises(ValueError):
            validate_target("example.com")


class TestNormalizer(unittest.TestCase):
    def test_normalize_custom_finding(self):
        from modules.normalizer import normalize_custom_finding
        raw = {"title": "Test", "severity": "high", "tool": "Custom", "cwe": "CWE-79"}
        result = normalize_custom_finding(raw)
        self.assertEqual(result["severity"], "High")
        self.assertEqual(result["title"], "Test")
        self.assertIn("id", result)
        self.assertEqual(result["status"], "Needs Manual Validation")

    def test_normalize_nuclei_finding(self):
        from modules.normalizer import normalize_nuclei_finding
        raw = {
            "info": {
                "name": "XSS Detected",
                "severity": "high",
                "description": "Cross-site scripting found",
                "classification": {"cve-id": ["CVE-2021-1234"], "cwe-id": ["CWE-79"]},
                "reference": ["https://ref.example.com"],
                "remediation": "Sanitize input",
            },
            "matched-at": "http://target.com/page",
            "extracted-results": "alert(1)",
        }
        result = normalize_nuclei_finding(raw)
        self.assertEqual(result["title"], "XSS Detected")
        self.assertEqual(result["severity"], "High")
        self.assertEqual(result["cve"], "CVE-2021-1234")
        self.assertEqual(result["cwe"], "CWE-79")
        self.assertEqual(result["tool"], "Nuclei")
        self.assertEqual(result["status"], "Potential")

    def test_normalize_zap_finding(self):
        from modules.normalizer import normalize_zap_finding
        alert = {
            "name": "SQL Injection", "riskcode": "3", "confidence": "2",
            "url": "http://target.com/login", "method": "POST",
            "param": "username", "description": "SQL injection found",
            "solution": "Use parameterized queries", "evidence": "' OR 1=1",
            "cweid": "89", "pluginid": "40018", "reference": "https://owasp.org",
        }
        result = normalize_zap_finding(alert)
        self.assertEqual(result["title"], "SQL Injection")
        self.assertEqual(result["severity"], "High")
        self.assertEqual(result["tool"], "ZAP")
        self.assertEqual(result["cwe"], "CWE-89")
        self.assertEqual(result["parameter"], "username")

    def test_normalize_zap_no_cwe(self):
        from modules.normalizer import normalize_zap_finding
        alert = {"name": "Info Leak", "riskcode": "0", "cweid": "-1"}
        result = normalize_zap_finding(alert)
        self.assertEqual(result["cwe"], "")
        self.assertEqual(result["severity"], "Informational")

    def test_normalize_nmap_finding(self):
        from modules.normalizer import normalize_nmap_finding
        port_info = {"port": "80", "protocol": "tcp", "service": "http",
                     "version": "Apache 2.4", "raw_line": "80/tcp open http Apache 2.4"}
        result = normalize_nmap_finding("example.com", port_info)
        self.assertIn("80", result["title"])
        self.assertEqual(result["severity"], "Informational")
        self.assertEqual(result["tool"], "Nmap")

    def test_severity_normalization(self):
        from modules.normalizer import _normalize_severity
        self.assertEqual(_normalize_severity("info"), "Informational")
        self.assertEqual(_normalize_severity("CRITICAL"), "Critical")
        self.assertEqual(_normalize_severity(""), "Informational")
        self.assertEqual(_normalize_severity("medium"), "Medium")


class TestDeduplicator(unittest.TestCase):
    def test_dedup_same_finding(self):
        from modules.deduplicator import deduplicate
        findings = [
            {"title": "Missing CSP", "cwe": "CWE-693", "endpoint": "/", "parameter": "",
             "tool": "Custom", "severity": "Medium", "evidence": "ev1"},
            {"title": "Missing CSP", "cwe": "CWE-693", "endpoint": "/", "parameter": "",
             "tool": "ZAP", "severity": "Medium", "evidence": "ev2"},
        ]
        result = deduplicate(findings)
        self.assertEqual(len(result), 1)
        self.assertIn("Custom", result[0]["sources"])
        self.assertIn("ZAP", result[0]["sources"])

    def test_dedup_different_endpoints(self):
        from modules.deduplicator import deduplicate
        findings = [
            {"title": "XSS", "cwe": "CWE-79", "endpoint": "/page1", "parameter": "",
             "tool": "ZAP", "severity": "High", "evidence": ""},
            {"title": "XSS", "cwe": "CWE-79", "endpoint": "/page2", "parameter": "",
             "tool": "ZAP", "severity": "High", "evidence": ""},
        ]
        result = deduplicate(findings)
        self.assertEqual(len(result), 2)

    def test_dedup_keeps_highest_severity(self):
        from modules.deduplicator import deduplicate
        findings = [
            {"title": "Issue", "cwe": "", "endpoint": "/", "parameter": "",
             "tool": "A", "severity": "Low", "evidence": ""},
            {"title": "Issue", "cwe": "", "endpoint": "/", "parameter": "",
             "tool": "B", "severity": "High", "evidence": ""},
        ]
        result = deduplicate(findings)
        self.assertEqual(result[0]["severity"], "High")

    def test_dedup_empty(self):
        from modules.deduplicator import deduplicate
        self.assertEqual(deduplicate([]), [])


class TestRisk(unittest.TestCase):
    def test_count_by_severity(self):
        from modules.risk import count_by_severity
        findings = [
            {"severity": "High"}, {"severity": "High"},
            {"severity": "Low"}, {"severity": "Informational"},
        ]
        counts = count_by_severity(findings)
        self.assertEqual(counts["High"], 2)
        self.assertEqual(counts["Low"], 1)
        self.assertEqual(counts["Critical"], 0)

    def test_highest_severity(self):
        from modules.risk import highest_severity
        self.assertEqual(highest_severity("Low", "High"), "High")
        self.assertEqual(highest_severity("Critical", "Low"), "Critical")


class TestCustomChecks(unittest.TestCase):
    def test_missing_headers(self):
        from modules.custom_checks import check_security_headers
        headers = {"Content-Type": "text/html", "Server": "nginx"}
        findings = check_security_headers(headers)
        titles = [f["title"] for f in findings]
        self.assertIn("Missing Content-Security-Policy header", titles)
        self.assertIn("Missing Strict-Transport-Security header", titles)

    def test_all_headers_present(self):
        from modules.custom_checks import check_security_headers
        headers = {
            "Content-Security-Policy": "default-src 'self'",
            "Strict-Transport-Security": "max-age=31536000",
            "X-Content-Type-Options": "nosniff",
            "X-Frame-Options": "DENY",
        }
        findings = check_security_headers(headers)
        # Should only have info-leak findings (if any), not missing header findings
        missing = [f for f in findings if f["title"].startswith("Missing")]
        self.assertEqual(len(missing), 0)

    def test_server_version_disclosure(self):
        from modules.custom_checks import check_security_headers
        headers = {
            "Content-Security-Policy": "x", "Strict-Transport-Security": "x",
            "X-Content-Type-Options": "x", "X-Frame-Options": "x",
            "Server": "Apache/2.4.51",
        }
        findings = check_security_headers(headers)
        info_leak = [f for f in findings if "disclosure" in f["title"].lower()]
        self.assertTrue(len(info_leak) > 0)


class TestNmapParsing(unittest.TestCase):
    def test_parse_nmap_ports(self):
        from modules.nmap_scan import _parse_nmap_ports
        stdout = """Starting Nmap 7.94 ( https://nmap.org )
PORT     STATE SERVICE  VERSION
80/tcp   open  http     Apache httpd 2.4.51
443/tcp  open  ssl/http Apache httpd 2.4.51
22/tcp   open  ssh      OpenSSH 8.9
"""
        ports = _parse_nmap_ports(stdout)
        self.assertEqual(len(ports), 3)
        self.assertEqual(ports[0]["port"], "80")
        self.assertEqual(ports[0]["service"], "http")

    @patch("modules.nmap_scan.subprocess.run")
    def test_nmap_not_installed(self, mock_run):
        mock_run.side_effect = FileNotFoundError
        from modules.nmap_scan import run_nmap
        with tempfile.TemporaryDirectory() as tmpdir:
            with patch("modules.nmap_scan.cfg") as mock_cfg:
                mock_cfg.NMAP_TIMEOUT = 10
                mock_cfg.RAW_DIR = tmpdir
                result = run_nmap("127.0.0.1")
        self.assertIn("not installed", result["error"])


class TestNucleiParsing(unittest.TestCase):
    @patch("modules.nuclei_scan.subprocess.run")
    def test_nuclei_parses_jsonl(self, mock_run):
        lines = [
            json.dumps({"info": {"name": "Test", "severity": "low"}, "matched-at": "http://x.com"}),
            json.dumps({"info": {"name": "Test2", "severity": "high"}, "matched-at": "http://x.com/2"}),
        ]
        mock_run.return_value = MagicMock(stdout="\n".join(lines), stderr="", returncode=0)
        from modules.nuclei_scan import run_nuclei
        with tempfile.TemporaryDirectory() as tmpdir:
            with patch("modules.nuclei_scan.cfg") as mock_cfg:
                mock_cfg.NUCLEI_TIMEOUT = 10
                mock_cfg.NUCLEI_EXTRA_ARGS = []
                mock_cfg.RAW_DIR = tmpdir
                result = run_nuclei("http://x.com")
        self.assertEqual(len(result), 2)

    @patch("modules.nuclei_scan.subprocess.run")
    def test_nuclei_not_installed(self, mock_run):
        mock_run.side_effect = FileNotFoundError
        from modules.nuclei_scan import run_nuclei
        with tempfile.TemporaryDirectory() as tmpdir:
            with patch("modules.nuclei_scan.cfg") as mock_cfg:
                mock_cfg.NUCLEI_TIMEOUT = 10
                mock_cfg.NUCLEI_EXTRA_ARGS = []
                mock_cfg.RAW_DIR = tmpdir
                result = run_nuclei("http://x.com")
        self.assertEqual(result, [])


class TestZapParsing(unittest.TestCase):
    @patch("modules.zap_scan.requests.get")
    def test_zap_unavailable(self, mock_get):
        mock_get.side_effect = Exception("Connection refused")
        from modules.zap_scan import check_zap_available
        self.assertFalse(check_zap_available())

    @patch("modules.zap_scan.requests.get")
    def test_zap_available(self, mock_get):
        mock_response = MagicMock()
        mock_response.json.return_value = {"version": "2.14.0"}
        mock_response.raise_for_status = MagicMock()
        mock_get.return_value = mock_response
        from modules.zap_scan import check_zap_available
        self.assertTrue(check_zap_available())

    def test_zap_run_unavailable(self):
        from modules.zap_scan import run_zap
        with patch("modules.zap_scan.check_zap_available", return_value=False):
            result = run_zap("http://example.com")
        self.assertIn("not reachable", result["error"])
        self.assertEqual(result["alerts"], [])


class TestReportGeneration(unittest.TestCase):
    def test_pdf_with_findings(self):
        from report_generator import generate_report
        findings = [
            {"title": "XSS", "severity": "High", "confidence": "High",
             "endpoint": "/page", "parameter": "q", "description": "XSS found",
             "impact": "Session hijack", "remediation": "Sanitize",
             "evidence": "<script>", "tool": "ZAP", "sources": ["ZAP"],
             "cwe": "CWE-79", "cve": "", "cvss": None, "owasp": "A03",
             "status": "Potential", "references": "https://owasp.org"},
        ]
        with tempfile.NamedTemporaryFile(suffix=".pdf", delete=False) as f:
            path = f.name
        try:
            generate_report("http://example.com", findings, path)
            self.assertTrue(os.path.exists(path))
            self.assertGreater(os.path.getsize(path), 500)
        finally:
            os.unlink(path)

    def test_pdf_empty_findings(self):
        from report_generator import generate_report
        with tempfile.NamedTemporaryFile(suffix=".pdf", delete=False) as f:
            path = f.name
        try:
            generate_report("http://example.com", [], path)
            self.assertTrue(os.path.exists(path))
            self.assertGreater(os.path.getsize(path), 500)
        finally:
            os.unlink(path)

    def test_pdf_html_in_description(self):
        """Ensure HTML/XML in descriptions doesn't crash ReportLab."""
        from report_generator import generate_report
        findings = [
            {"title": "Test <script>alert(1)</script>", "severity": "Medium",
             "confidence": "Low", "endpoint": "/", "parameter": "",
             "description": '<img src="x" onerror="alert(1)">', "impact": "",
             "remediation": "", "evidence": "a&b<c>d", "tool": "Custom",
             "sources": ["Custom"], "cwe": "", "cve": "", "cvss": None,
             "owasp": "", "status": "Potential", "references": ""},
        ]
        with tempfile.NamedTemporaryFile(suffix=".pdf", delete=False) as f:
            path = f.name
        try:
            generate_report("http://example.com", findings, path)
            self.assertTrue(os.path.exists(path))
        finally:
            os.unlink(path)


class TestJSONOutput(unittest.TestCase):
    def test_json_serializable(self):
        from modules.normalizer import normalize_custom_finding
        raw = {"title": "Test", "severity": "Medium", "tool": "Custom"}
        result = normalize_custom_finding(raw)
        # Should not raise
        serialized = json.dumps(result)
        parsed = json.loads(serialized)
        self.assertEqual(parsed["title"], "Test")


if __name__ == "__main__":
    unittest.main()
