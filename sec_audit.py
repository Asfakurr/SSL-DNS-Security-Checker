#!/usr/bin/env python3
"""
SSL/TLS & DNS Security Checker (sec_audit.py)

Inspects domains for SSL/TLS certificate health (expiry, protocol version,
cipher strength, SANs) and DNS security posture (A/AAAA, MX, CAA, SPF, DMARC).
Supports concurrent batch scanning and JSON report export.
"""

from __future__ import annotations

import argparse
import concurrent.futures
import datetime
import json
import socket
import ssl
import sys
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

try:
    import dns.resolver  # type: ignore

    HAS_DNSPYTHON = True
except ImportError:
    HAS_DNSPYTHON = False


WEAK_TLS_VERSIONS = {"SSLv2", "SSLv3", "TLSv1", "TLSv1.1"}


@dataclass
class Finding:
    category: str
    status: str
    check: str
    detail: str


@dataclass
class DomainReport:
    domain: str
    scanned_at: str
    score: int = 100
    tls: dict[str, Any] = field(default_factory=dict)
    dns: dict[str, Any] = field(default_factory=dict)
    findings: list[Finding] = field(default_factory=list)
    error: str | None = None


def parse_cert_date(date_str: str) -> datetime.datetime:
    return datetime.datetime.strptime(date_str, "%b %d %H:%M:%S %Y %Z").replace(
        tzinfo=datetime.timezone.utc
    )


def inspect_tls(domain: str, port: int = 443, timeout: float = 5.0) -> tuple[dict[str, Any], list[Finding]]:
    findings: list[Finding] = []
    tls_info: dict[str, Any] = {}
    context = ssl.create_default_context()

    try:
        with socket.create_connection((domain, port), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert() or {}
                protocol = ssock.version() or "Unknown"
                cipher_name, cipher_proto, cipher_bits = ssock.cipher() or ("Unknown", "Unknown", 0)

                subject = dict(x[0] for x in cert.get("subject", ()))
                issuer = dict(x[0] for x in cert.get("issuer", ()))
                sans = [val for kind, val in cert.get("subjectAltName", ()) if kind == "DNS"]

                not_after_raw = cert.get("notAfter", "")
                days_remaining = None
                if not_after_raw:
                    expires_at = parse_cert_date(not_after_raw)
                    now = datetime.datetime.now(datetime.timezone.utc)
                    days_remaining = (expires_at - now).days

                tls_info = {
                    "protocol": protocol,
                    "cipher": cipher_name,
                    "cipher_bits": cipher_bits,
                    "subject_cn": subject.get("commonName", ""),
                    "issuer_org": issuer.get("organizationName", issuer.get("commonName", "")),
                    "expires_at": not_after_raw,
                    "days_remaining": days_remaining,
                    "san_count": len(sans),
                }

                if protocol in WEAK_TLS_VERSIONS:
                    findings.append(Finding("TLS", "FAIL", "Protocol Version", f"Deprecated protocol negotiated: {protocol}"))
                else:
                    findings.append(Finding("TLS", "PASS", "Protocol Version", f"Strong protocol negotiated: {protocol}"))

                if cipher_bits and cipher_bits < 128:
                    findings.append(Finding("TLS", "FAIL", "Cipher Strength", f"Weak cipher {cipher_name} ({cipher_bits} bits)"))
                else:
                    findings.append(Finding("TLS", "PASS", "Cipher Strength", f"{cipher_name} ({cipher_bits} bits)"))

                if days_remaining is None:
                    findings.append(Finding("TLS", "WARN", "Certificate Expiry", "Could not determine certificate expiration date"))
                elif days_remaining < 0:
                    findings.append(Finding("TLS", "FAIL", "Certificate Expiry", f"Certificate expired {abs(days_remaining)} days ago"))
                elif days_remaining < 14:
                    findings.append(Finding("TLS", "FAIL", "Certificate Expiry", f"Critical: expires in {days_remaining} days"))
                elif days_remaining < 30:
                    findings.append(Finding("TLS", "WARN", "Certificate Expiry", f"Renew soon: expires in {days_remaining} days"))
                else:
                    findings.append(Finding("TLS", "PASS", "Certificate Expiry", f"Valid for {days_remaining} days"))

                if sans:
                    findings.append(Finding("TLS", "PASS", "SANs", f"{len(sans)} DNS name(s) present"))
                else:
                    findings.append(Finding("TLS", "WARN", "SANs", "No DNS Subject Alternative Names found"))

    except (OSError, ssl.SSLError, ValueError) as exc:
        findings.append(Finding("TLS", "FAIL", "TLS Connection", str(exc)))

    return tls_info, findings


def _doh_query(domain: str, record_type: str, timeout: float = 5.0) -> list[str]:
    query = urllib.parse.urlencode({"name": domain, "type": record_type})
    request = urllib.request.Request(
        f"https://cloudflare-dns.com/dns-query?{query}",
        headers={"accept": "application/dns-json"},
    )
    with urllib.request.urlopen(request, timeout=timeout) as response:
        payload = json.loads(response.read().decode("utf-8"))

    answers = payload.get("Answer", [])
    return [str(answer.get("data", "")) for answer in answers]


def resolve_records(domain: str, record_type: str, timeout: float = 5.0) -> list[str]:
    if HAS_DNSPYTHON:
        resolver = dns.resolver.Resolver()
        resolver.timeout = timeout
        resolver.lifetime = timeout
        try:
            answers = resolver.resolve(domain, record_type)
            return [answer.to_text().strip('"') for answer in answers]
        except Exception:
            return []
    try:
        return _doh_query(domain, record_type, timeout)
    except (OSError, urllib.error.URLError, json.JSONDecodeError):
        return []


def evaluate_spf(records: list[str]) -> tuple[str | None, Finding]:
    spf_records = [record for record in records if record.lower().startswith("v=spf1")]
    if not spf_records:
        return None, Finding("DNS", "FAIL", "SPF Record", "No SPF record found")
    if len(spf_records) > 1:
        return None, Finding("DNS", "FAIL", "SPF Record", "Multiple SPF records found")
    record = spf_records[0]
    if "+all" in record.lower():
        return record, Finding("DNS", "FAIL", "SPF Record", f"Permissive SPF configured (+all): {record}")
    if "-all" in record.lower():
        return record, Finding("DNS", "PASS", "SPF Record", f"Strict SPF configured (-all): {record}")
    return record, Finding("DNS", "WARN", "SPF Record", f"SPF exists but does not use -all: {record}")


def evaluate_dmarc(records: list[str]) -> tuple[str | None, Finding]:
    dmarc_records = [record for record in records if record.lower().startswith("v=dmarc1")]
    if not dmarc_records:
        return None, Finding("DNS", "FAIL", "DMARC Policy", "No DMARC record found")
    record = dmarc_records[0]
    policy = next((part.split("=", 1)[1].lower() for part in record.split(";") if part.strip().lower().startswith("p=")), "")
    if policy == "reject":
        return record, Finding("DNS", "PASS", "DMARC Policy", f"Enforced DMARC policy (p=reject): {record}")
    if policy == "quarantine":
        return record, Finding("DNS", "PASS", f"DMARC Policy", f"Enforced DMARC policy (p=quarantine): {record}")
    return record, Finding("DNS", "WARN", "DMARC Policy", f"Monitor-only DMARC policy: {record}")


def inspect_dns(domain: str, timeout: float = 5.0) -> tuple[dict[str, Any], list[Finding]]:
    dns_info: dict[str, Any] = {}
    findings: list[Finding] = []

    for record_type in ("A", "AAAA", "MX", "CAA"):
        values = resolve_records(domain, record_type, timeout)
        dns_info[record_type.lower()] = values

    if dns_info["a"] or dns_info["aaaa"]:
        findings.append(Finding("DNS", "PASS", "Address Records", "A/AAAA record(s) found"))
    else:
        findings.append(Finding("DNS", "WARN", "Address Records", "No A or AAAA record found"))

    if dns_info["mx"]:
        findings.append(Finding("DNS", "PASS", "MX Record", f"{len(dns_info['mx'])} MX record(s) found"))
    else:
        findings.append(Finding("DNS", "WARN", "MX Record", "No MX record found"))

    spf_records = resolve_records(domain, "TXT", timeout)
    dmarc_records = resolve_records(f"_dmarc.{domain}", "TXT", timeout)
    dns_info["spf"], spf_finding = evaluate_spf(spf_records)
    dns_info["dmarc"], dmarc_finding = evaluate_dmarc(dmarc_records)
    findings.extend([spf_finding, dmarc_finding])

    if dns_info["caa"]:
        findings.append(Finding("DNS", "PASS", "CAA Record", f"{len(dns_info['caa'])} CAA record(s) found"))
    else:
        findings.append(Finding("DNS", "WARN", "CAA Record", "No CAA record found; any trusted CA can issue certificates"))

    return dns_info, findings


def calculate_score(findings: list[Finding]) -> int:
    score = 100
    for finding in findings:
        if finding.status == "FAIL":
            score -= 14
        elif finding.status == "WARN":
            score -= 7
    return max(0, min(100, score))


def audit_domain(domain: str, timeout: float = 5.0) -> DomainReport:
    scanned_at = datetime.datetime.now(datetime.timezone.utc).isoformat()
    report = DomainReport(domain=domain, scanned_at=scanned_at)

    try:
        report.tls, tls_findings = inspect_tls(domain, timeout=timeout)
        report.dns, dns_findings = inspect_dns(domain, timeout=timeout)
        report.findings = tls_findings + dns_findings
        report.score = calculate_score(report.findings)
    except Exception as exc:
        report.error = str(exc)
        report.score = 0

    return report


def print_report(report: DomainReport) -> None:
    print("=" * 68)
    print(f"Domain: {report.domain}  |  Score: {report.score}/100  |  Scanned: {report.scanned_at}")
    print("-" * 68)
    if report.tls:
        print(
            f"TLS: {report.tls.get('protocol', 'Unknown')} | "
            f"{report.tls.get('cipher', 'Unknown')} ({report.tls.get('cipher_bits', 0)}b) | "
            f"Issuer: {report.tls.get('issuer_org', 'Unknown')}"
        )
    addresses = report.dns.get("a", []) + report.dns.get("aaaa", [])
    if addresses:
        print(f"DNS A/AAAA: {', '.join(addresses)}")
    for finding in report.findings:
        print(f"  [{finding.status}] [{finding.category}] {finding.check}: {finding.detail}")
    if report.error:
        print(f"  [ERROR] {report.error}")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Audit SSL/TLS and DNS security for domains.")
    parser.add_argument("domains", nargs="*", help="Domain names to audit")
    parser.add_argument("--file", type=Path, help="File containing one domain per line")
    parser.add_argument("--workers", type=int, default=5, help="Concurrent worker count")
    parser.add_argument("--out", type=Path, help="Write JSON report to this file")
    parser.add_argument("--timeout", type=float, default=5.0, help="Network timeout in seconds")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    domains = list(args.domains)

    if args.file:
        domains.extend(
            line.strip()
            for line in args.file.read_text(encoding="utf-8").splitlines()
            if line.strip() and not line.lstrip().startswith("#")
        )

    domains = list(dict.fromkeys(domains))
    if not domains:
        print("No domains supplied. Use a domain argument or --file.", file=sys.stderr)
        return 2

    workers = max(1, args.workers)
    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as executor:
        reports = list(executor.map(lambda d: audit_domain(d, args.timeout), domains))

    for report in reports:
        print_report(report)

    if args.out:
        payload = []
        for report in reports:
            item = asdict(report)
            payload.append(item)
        args.out.write_text(json.dumps(payload, indent=2), encoding="utf-8")
        print(f"\nJSON report written to {args.out}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
