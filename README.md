# SSL/TLS & DNS Security Checker

A lightweight, concurrent Python CLI tool that audits domains for **SSL/TLS certificate health** and **DNS security posture** (SPF, DMARC, CAA, MX, and A records), producing a 0–100 security score and exportable JSON reports.

## What It Checks

* **TLS Handshake & Protocol:** Flags deprecated protocols (`TLSv1`, `TLSv1.1`, `SSLv3`) and weak ciphers (`< 128` bits).

* **Certificate Health:** Inspects issuer, Subject Alternative Names (SANs), trust verification, and days until expiration (`< 30` days warning, `< 14` days critical).

* **Email & Spoofing Protection (SPF & DMARC):** Detects missing records, RFC 7208 duplicate SPF violations, overly permissive `+all` policies, and monitor-only `p=none` DMARC configurations.

* **Certificate Authority Authorization (CAA):** Checks whether the domain restricts which CAs are permitted to issue certificates.

* **Zero-Dependency Fallback:** Uses `dnspython` when installed and automatically falls back to Cloudflare DNS-over-HTTPS (`https://cloudflare-dns.com/dns-query`) using Python's standard library.

## Quick Start

```bash
# Audit a single domain
python3 sec_audit.py github.com

# Audit multiple domains concurrently and save JSON output
python3 sec_audit.py github.com cloudflare.com --out report.json

# Audit from a file (one domain per line)
python3 sec_audit.py --file domains.txt --workers 10
```

## Running Tests

```bash
python3 -m unittest test_sec_audit.py -v
```

## Sample Output

```
====================================================================
Domain: example.com  |  Score: 92/100  |  Scanned: 2026-11-12T17:15:00+00:00
--------------------------------------------------------------------
TLS: TLSv1.3 | TLS_AES_256_GCM_SHA384 (256b) | Issuer: DigiCert Inc
DNS A: 93.184.216.34

  [PASS] [TLS] Protocol Version: Strong protocol negotiated: TLSv1.3
  [PASS] [TLS] Cipher Strength: TLS_AES_256_GCM_SHA384 (256 bits)
  [PASS] [TLS] Certificate Expiry: Valid for 142 days
  [PASS] [DNS] SPF Record: Strict SPF configured (-all): v=spf1 -all
  [PASS] [DNS] DMARC Policy: Enforced DMARC policy (p=reject): v=DMARC1; p=reject;
  [WARN] [DNS] CAA Record: No CAA record found; any trusted CA can issue certificates
```

