# CyberShield Toolkit Testing Documentation

This document outlines the testing procedures and recent clean test results for the **CyberShield Toolkit**. 

These tests demonstrate the core functionalities of each module against external testing and standard domains. The test reports are automatically saved as JSON and TXT in the `reports/` directory, while application behaviors are logged in `logs/cybershield.log`.

## 1. Port Scanner Module
**Target:** `scanme.nmap.org`
**Command Run:** `python main.py --module port_scanner --target scanme.nmap.org`

**Result:**
The port scanner successfully identified standard open ports within the 1-1024 range.
```text
        Open Ports         
+-------------------------+
| Port | Status | Service |
|------+--------+---------|
| 22   | OPEN   | SSH     |
| 80   | OPEN   | HTTP    |
+-------------------------+
```

## 2. DNS Lookup Module
**Target:** `example.com`
**Command Run:** `python main.py --module dns_lookup --target example.com`

**Result:**
The DNS lookup fetched the standard DNS configuration including A, MX, and Name Server (NS) records.
```text
             DNS Records             
+-----------------------------------+
| Type | Value                      |
|------+----------------------------|
| A    | 104.20.23.154              |
| A    | 172.66.147.243             |
| MX   | .                          |
| NS   | hera.ns.cloudflare.com.    |
| NS   | elliott.ns.cloudflare.com. |
+-----------------------------------+
```

## 3. WHOIS Lookup Module
**Target:** `example.com`
**Command Run:** `python main.py --module whois_lookup --target example.com`

**Result:**
The WHOIS lookup accurately parsed domain registration information.
```text
                        WHOIS Information                         
+----------------------------------------------------------------+
| Property        | Value                                        |
|-----------------+----------------------------------------------|
| Registrar       | RESERVED-Internet Assigned Numbers Authority |
| Creation Date   | 1995-08-14 04:00:00                          |
| Expiration Date | 2026-08-13 04:00:00                          |
+----------------------------------------------------------------+
```

## 4. Security Headers Checker Module
**Target:** `example.com`
**Command Run:** `python main.py --module header_checker --target example.com`

**Result:**
Evaluated HTTP headers against security best practices (e.g. HSTS, CSP, X-Frame-Options).
```text
       Security Headers       
+----------------------------+
| Header           | Status  |
|------------------+---------|
| HSTS             | Missing |
| CSP              | Missing |
| X-Frame-Options  | Missing |
| X-XSS-Protection | Missing |
+----------------------------+
```

## 5. Subdomain Finder Module
**Target:** `example.com`
**Command Run:** `python main.py --module subdomain_finder --target example.com`

**Result:**
Searched for and discovered common subdomains and their resolved IP addresses.
```text
       Discovered Subdomains       
+---------------------------------+
| Subdomain       | IP Address    |
|-----------------+---------------|
| www.example.com | 104.20.23.154 |
+---------------------------------+
```

---
*Note: All output reports from these tests were successfully verified and the toolkit functions as expected without errors. The testing logs were cleared prior to this test run to ensure a clean slate.*
