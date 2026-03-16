import requests
import time
import json

# ── CONFIG ────────────────────────────────────────────────────────────────────
API_KEY  = "feffe3dba7f7229830238aed70518d8a79d4f36bdacae4dd693be61f634a5c40"   # Paste your VirusTotal API key here
BASE_URL = "https://www.virustotal.com/api/v3"
HEADERS  = {"x-apikey": API_KEY}

# ── HELPER: Print section header ──────────────────────────────────────────────
def header(title):
    print("\n" + "="*50)
    print(f"  {title}")
    print("="*50)

# ── HELPER: Print scan stats ──────────────────────────────────────────────────
def print_stats(stats):
    print(f"  Malicious   : {stats.get('malicious', 0)}")
    print(f"  Suspicious  : {stats.get('suspicious', 0)}")
    print(f"  Harmless    : {stats.get('harmless', 0)}")
    print(f"  Undetected  : {stats.get('undetected', 0)}")
    total = sum(stats.values())
    score = stats.get('malicious', 0)
    print(f"  Safety Score: {score}/{total} engines flagged as malicious")

# ── HELPER: Wait for analysis to complete ─────────────────────────────────────
def wait_for_result(analysis_id):
    print("  Waiting for analysis", end="", flush=True)
    for _ in range(15):
        time.sleep(3)
        print(".", end="", flush=True)
        response = requests.get(
            f"{BASE_URL}/analyses/{analysis_id}",
            headers=HEADERS
        )
        result = response.json()
        status = result["data"]["attributes"]["status"]
        if status == "completed":
            print(" Done!")
            return result
    print(" Timed out.")
    return None

# ── FEATURE 1: Scan a URL ─────────────────────────────────────────────────────
def scan_url(url):
    header("URL SCAN")
    print(f"  Target URL : {url}")

    response = requests.post(
        f"{BASE_URL}/urls",
        headers=HEADERS,
        data={"url": url}
    )

    if response.status_code != 200:
        print(f"  Error: {response.status_code} - {response.text}")
        return

    analysis_id = response.json()["data"]["id"]
    print(f"  Analysis ID: {analysis_id}")

    result = wait_for_result(analysis_id)
    if result:
        stats = result["data"]["attributes"]["stats"]
        print_stats(stats)

# ── FEATURE 2: Scan a Local File ─────────────────────────────────────────────
def scan_file(filepath):
    header("FILE SCAN")
    print(f"  File: {filepath}")

    try:
        with open(filepath, "rb") as f:
            response = requests.post(
                f"{BASE_URL}/files",
                headers=HEADERS,
                files={"file": f}
            )
    except FileNotFoundError:
        print(f"  Error: File '{filepath}' not found!")
        return

    if response.status_code != 200:
        print(f"  Error: {response.status_code} - {response.text}")
        return

    analysis_id = response.json()["data"]["id"]
    print(f"  Analysis ID: {analysis_id}")

    result = wait_for_result(analysis_id)
    if result:
        stats = result["data"]["attributes"]["stats"]
        print_stats(stats)

# ── FEATURE 3: Lookup by File Hash (MD5/SHA256) ───────────────────────────────
def lookup_hash(file_hash):
    header("HASH LOOKUP")
    print(f"  Hash: {file_hash}")

    response = requests.get(
        f"{BASE_URL}/files/{file_hash}",
        headers=HEADERS
    )

    if response.status_code == 404:
        print("  Result: Hash not found in VirusTotal database.")
        return
    if response.status_code != 200:
        print(f"  Error: {response.status_code} - {response.text}")
        return

    data  = response.json()["data"]["attributes"]
    stats = data["last_analysis_stats"]
    print(f"  File Name   : {data.get('meaningful_name', 'Unknown')}")
    print(f"  File Type   : {data.get('type_description', 'Unknown')}")
    print(f"  File Size   : {data.get('size', 'Unknown')} bytes")
    print_stats(stats)

# ── FEATURE 4: Get IP Address Report ─────────────────────────────────────────
def scan_ip(ip_address):
    header("IP ADDRESS SCAN")
    print(f"  IP: {ip_address}")

    response = requests.get(
        f"{BASE_URL}/ip_addresses/{ip_address}",
        headers=HEADERS
    )

    if response.status_code != 200:
        print(f"  Error: {response.status_code} - {response.text}")
        return

    data  = response.json()["data"]["attributes"]
    stats = data.get("last_analysis_stats", {})
    print(f"  Country     : {data.get('country', 'Unknown')}")
    print(f"  Owner       : {data.get('as_owner', 'Unknown')}")
    print_stats(stats)

# ── FEATURE 5: Get Domain Report ─────────────────────────────────────────────
def scan_domain(domain):
    header("DOMAIN SCAN")
    print(f"  Domain: {domain}")

    response = requests.get(
        f"{BASE_URL}/domains/{domain}",
        headers=HEADERS
    )

    if response.status_code != 200:
        print(f"  Error: {response.status_code} - {response.text}")
        return

    data  = response.json()["data"]["attributes"]
    stats = data.get("last_analysis_stats", {})
    print(f"  Reputation  : {data.get('reputation', 'Unknown')}")
    print(f"  Categories  : {data.get('categories', {})}")
    print_stats(stats)

# ── MAIN ──────────────────────────────────────────────────────────────────────
if __name__ == "__main__":

    print("\n" + "*"*50)
    print("*   VirusTotal API - Security Scanner         *")
    print("*"*50)

    # 1. Scan a safe URL
    scan_url("http://example.com")

    # 2. Scan a local file (creates a test file automatically)
    with open("test_file.txt", "w") as f:
        f.write("This is a harmless test file for VirusTotal scanning.")
    scan_file("test_file.txt")

    # 3. Lookup a known hash (EICAR antivirus test file - safe to use)
    lookup_hash("275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f")

    # 4. Scan an IP address
    scan_ip("8.8.8.8")

    # 5. Scan a domain
    scan_domain("google.com")