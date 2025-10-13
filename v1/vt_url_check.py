# save as vt_url_check.py
import os, time, base64, requests

API_KEY = os.getenv("VT_API_KEY")
if not API_KEY:
    raise SystemExit("Set VT_API_KEY env var")

HEADERS = {"x-apikey": API_KEY, "Accept": "application/json"}

def submit_url(url):
    r = requests.post("https://www.virustotal.com/api/v3/urls",
                      headers=HEADERS, data={"url": url}, timeout=30)
    r.raise_for_status()
    return r.json()["data"]["id"]  # this is an analysis id

def get_analysis(analysis_id):
    r = requests.get(f"https://www.virustotal.com/api/v3/analyses/{analysis_id}",
                     headers=HEADERS, timeout=30)
    r.raise_for_status()
    return r.json()

def url_id_from_url(url):
    enc = base64.urlsafe_b64encode(url.encode()).decode()
    return enc.rstrip("=")   # VT expects base64 url-safe without padding

def get_url_report(url_id):
    r = requests.get(f"https://www.virustotal.com/api/v3/urls/{url_id}",
                     headers=HEADERS, timeout=30)
    r.raise_for_status()
    return r.json()

def check_url(url, poll_seconds=2, max_tries=15):
    analysis_id = submit_url(url)
    for _ in range(max_tries):
        analysis = get_analysis(analysis_id)
        status = analysis["data"]["attributes"]["status"]
        if status == "completed":
            break
        time.sleep(poll_seconds)
    url_id = url_id_from_url(url)
    report = get_url_report(url_id)
    stats = report["data"]["attributes"].get("last_analysis_stats", {})
    malicious = stats.get("malicious", 0)
    suspicious = stats.get("suspicious", 0)
    return {"url": url, "malicious": malicious, "suspicious": suspicious, "stats": stats, "raw": report}

if __name__ == "__main__":
    import sys
    if len(sys.argv) < 2:
        print("usage: python vt_url_check.py https://example.com")
        raise SystemExit(1)
    out = check_url(sys.argv[1])
    print(f"malicious={out['malicious']} suspicious={out['suspicious']} stats={out['stats']}")

