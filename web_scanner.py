import requests
from urllib.parse import urljoin
from bs4 import BeautifulSoup

# ------------------------------
# 1. Website Reachability Check
# ------------------------------
def check_website(url):
    print(f"\n[+] Checking website: {url}")
    try:
        r = requests.get(url, timeout=5)
        print("[✓] Website is reachable")
        return r
    except:
        print("[-] Website is NOT reachable")
        return None


# ------------------------------
# 2. Security Header Scanner
# ------------------------------
def header_scan(response):
    print("\n--- Security Header Scan ---")

    headers = response.headers

    checks = {
        "X-Frame-Options": "Clickjacking Protection",
        "X-Content-Type-Options": "MIME Sniffing Protection",
        "Strict-Transport-Security": "HSTS Security",
        "Content-Security-Policy": "XSS Protection",
        "Referrer-Policy": "Privacy Protection",
        "Permissions-Policy": "Browser Permissions Control"
    }

    for header, purpose in checks.items():
        if header in headers:
            print(f"[✓] {header} found ({purpose})")
        else:
            print(f"[X] {header} MISSING ({purpose})")


# ------------------------------
# 3. Directory Scanner
# ------------------------------
def directory_scan(base_url):
    print("\n--- Directory Scan ---")

    dirs = [
        "admin", "login", "dashboard", "uploads", "backup",
        "test", "images", "api", "config", "server-status"
    ]

    for d in dirs:
        full_url = urljoin(base_url, d)
        try:
            r = requests.get(full_url, timeout=3)
            if r.status_code == 200:
                print(f"[✓] Found: {full_url}")
            else:
                print(f"[ ] {full_url} → {r.status_code}")
        except:
            print(f"[ ] {full_url} → unreachable")


# ------------------------------
# 4. Broken Link Scanner
# ------------------------------
def find_broken_links(url):
    print("\n--- Broken Link Finder ---")

    try:
        r = requests.get(url)
    except:
        print("[-] Cannot scan links. Website unreachable.")
        return

    soup = BeautifulSoup(r.text, "html.parser")

    links = set()
    for tag in soup.find_all("a"):
        href = tag.get("href")
        if href and href.startswith(("http", "/")):
            links.add(urljoin(url, href))

    print(f"[+] Found {len(links)} links")

    for link in links:
        try:
            res = requests.get(link, timeout=3)
            if res.status_code == 404:
                print(f"[X] Broken: {link}")
        except:
            print(f"[X] Broken: {link}")


# ------------------------------
# MAIN PROGRAM
# ------------------------------
def main():
    print("\n========== SIMPLE WEB VULNERABILITY SCANNER ==========")
    url = input("\nEnter website URL (example: https://example.com): ")

    if not url.startswith("http"):
        url = "https://" + url

    resp = check_website(url)
    if not resp:
        return

    header_scan(resp)
    directory_scan(url)
    find_broken_links(url)

    print("\nScan Completed ✔")


if __name__ == "__main__":
    main()
