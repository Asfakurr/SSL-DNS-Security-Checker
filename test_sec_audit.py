#!/usr/bin/env python3
"""Unit tests for sec_audit.py (runs completely offline using mocks)."""

import datetime
import unittest
from unittest.mock import MagicMock, patch

import sec_audit


class TestSecAudit(unittest.TestCase):
    def test_evaluate_spf_strict(self) -> None:
        val, finding = sec_audit.evaluate_spf(["v=spf1 include:_spf.google.com -all"])
        self.assertIsNotNone(val)
        self.assertEqual(finding.status, "PASS")

    def test_evaluate_spf_missing(self) -> None:
        val, finding = sec_audit.evaluate_spf(["google-site-verification=abc123"])
        self.assertIsNone(val)
        self.assertEqual(finding.status, "FAIL")

    def test_evaluate_spf_permissive_all(self) -> None:
        _, finding = sec_audit.evaluate_spf(["v=spf1 +all"])
        self.assertEqual(finding.status, "FAIL")

    def test_evaluate_dmarc_reject(self) -> None:
        _, finding = sec_audit.evaluate_dmarc(["v=DMARC1; p=reject; rua=mailto:sec@example.com"])
        self.assertEqual(finding.status, "PASS")

    def test_evaluate_dmarc_monitor_only(self) -> None:
        _, finding = sec_audit.evaluate_dmarc(["v=DMARC1; p=none;"])
        self.assertEqual(finding.status, "WARN")

    def test_calculate_score_bounds(self) -> None:
        findings = [
            sec_audit.Finding("TLS", "FAIL", "Protocol", "Deprecated"),
            sec_audit.Finding("DNS", "WARN", "CAA", "Missing"),
            sec_audit.Finding("TLS", "PASS", "Cipher", "AES256"),
        ]
        self.assertEqual(sec_audit.calculate_score(findings), 72)

        many_fails = [sec_audit.Finding("DNS", "FAIL", f"F{i}", "bad") for i in range(8)]
        self.assertEqual(sec_audit.calculate_score(many_fails), 0)

    @patch("sec_audit.socket.create_connection")
    @patch("sec_audit.ssl.create_default_context")
    def test_inspect_tls_healthy_cert(self, mock_ctx_factory: MagicMock, mock_conn: MagicMock) -> None:
        future_date = (
            datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=60)
        ).strftime("%b %d %H:%M:%S %Y GMT")

        mock_ssock = MagicMock()
        mock_ssock.version.return_value = "TLSv1.3"
        mock_ssock.cipher.return_value = ("TLS_AES_256_GCM_SHA384", "TLSv1.3", 256)
        mock_ssock.getpeercert.return_value = {
            "subject": ((("commonName", "example.com"),),),
            "issuer": ((("organizationName", "Let's Encrypt"),),),
            "subjectAltName": (("DNS", "example.com"), ("DNS", "www.example.com")),
            "notAfter": future_date,
        }
        mock_ctx_factory.return_value.wrap_socket.return_value.__enter__.return_value = mock_ssock

        tls_info, findings = sec_audit.inspect_tls("example.com")
        self.assertEqual(tls_info["protocol"], "TLSv1.3")
        self.assertEqual(tls_info["cipher_bits"], 256)
        self.assertTrue(all(f.status == "PASS" for f in findings))


if __name__ == "__main__":
    unittest.main()
