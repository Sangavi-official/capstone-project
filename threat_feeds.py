"""
GhostNet Threat Feeds — Phase 2 (LTSA)
========================================
Live threat intelligence from 4 sources:
  1. NIST NVD CVE API     — free, no key
  2. Shodan API           — paste your key below
  3. AbuseIPDB API        — paste your key below
  4. MITRE ATT&CK         — free, no key

SSL fix applied for Windows Python 3.12.
"""

import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

import requests
from datetime import datetime, timedelta, timezone

# ─── PASTE YOUR API KEYS HERE ─────────────────────────────
SHODAN_API_KEY   = "xkj8RSp4CUje2FXyHJtaaI4tWh1nuWjs"      
ABUSEIPDB_API_KEY = "ecea33fba3183fafe07fba0d510cf58750707d08203aba590570a4cebcfce7cf1ea6731de6e0d767"  

# ──────────────────────────────────────────────────────────


# ── 1. NIST NVD CVE FEED ──────────────────────────────────

def get_cve_score():
    """
    Fetches CVEs from last 7 days from NIST NVD.
    Returns normalized 0.0 (safe) to 1.0 (critical).
    Free — no key needed.
    """
    end   = datetime.now(timezone.utc).replace(tzinfo=None)
    start = end - timedelta(days=7)

    url    = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    params = {
        "pubStartDate":   start.strftime("%Y-%m-%dT%H:%M:%S.000"),
        "pubEndDate":     end.strftime("%Y-%m-%dT%H:%M:%S.000"),
        "resultsPerPage": 20
    }

    try:
        r = requests.get(url, params=params, timeout=15, verify=False)
        r.raise_for_status()
        vulns = r.json().get("vulnerabilities", [])

        scores  = []
        cve_ids = []
        for v in vulns:
            cve_id  = v["cve"].get("id", "unknown")
            metrics = v["cve"].get("metrics", {})
            if "cvssMetricV31" in metrics:
                s = metrics["cvssMetricV31"][0]["cvssData"]["baseScore"]
                scores.append(s); cve_ids.append((cve_id, s))
            elif "cvssMetricV30" in metrics:
                s = metrics["cvssMetricV30"][0]["cvssData"]["baseScore"]
                scores.append(s); cve_ids.append((cve_id, s))

        if scores:
            max_score  = max(scores)
            normalized = round(max_score / 10.0, 3)
            top3 = sorted(cve_ids, key=lambda x: x[1], reverse=True)[:3]
            print(f"  [CVE]  {len(scores)} CVEs this week")
            for cid, sc in top3:
                print(f"         {cid}  CVSS: {sc}")
            print(f"         Highest: {max_score} → Normalized: {normalized}")
            return normalized
        else:
            print("  [CVE]  No scored CVEs — default 0.3")
            return 0.3

    except requests.exceptions.Timeout:
        print("  [CVE]  Timeout — fallback 0.3")
        return 0.3
    except Exception as e:
        print(f"  [CVE]  Error: {e} — fallback 0.3")
        return 0.3


# ── 2. SHODAN FEED ────────────────────────────────────────

def get_shodan_score():
    """
    Queries Shodan for exposed hospital services.
    Returns normalized 0.0 (hidden) to 1.0 (fully exposed).
    """
    if SHODAN_API_KEY == "--":
        import random
        score = round(random.uniform(0.2, 0.6), 3)
        print(f"  [Shodan] No key — simulated score: {score}")
        return score

    try:
        url    = "https://api.shodan.io/shodan/host/count"
        params = {
            "key":   SHODAN_API_KEY,
            "query": "hospital port:8080,1883,443"
        }
        r     = requests.get(url, params=params, timeout=10)
        count = r.json().get("total", 0)
        score = round(min(1.0, count / 50000), 3)
        print(f"  [Shodan] {count} exposed hospital services → {score}")
        return score
    except Exception as e:
        print(f"  [Shodan] Error: {e} — fallback 0.4")
        return 0.4


# ── 3. ABUSEIPDB FEED ────────────────────────────────────

def get_abuse_score():
    """
    Fetches count of active malicious IPs from AbuseIPDB.
    Higher score = more attackers active globally right now.
    Returns normalized 0.0 to 1.0.
    """
    if ABUSEIPDB_API_KEY == "--":
        import random
        score = round(random.uniform(0.2, 0.5), 3)
        print(f"  [AbuseIPDB] No key — simulated score: {score}")
        return score

    try:
        url     = "https://api.abuseipdb.com/api/v2/blacklist"
        headers = {
            "Key":    ABUSEIPDB_API_KEY,
            "Accept": "application/json"
        }
        params = {"confidenceMinimum": 90, "limit": 100}
        r      = requests.get(url, headers=headers,
                              params=params, timeout=10)
        count  = len(r.json().get("data", []))
        score  = round(min(1.0, count / 100), 3)
        print(f"  [AbuseIPDB] {count} malicious IPs active → {score}")
        return score
    except Exception as e:
        print(f"  [AbuseIPDB] Error: {e} — fallback 0.3")
        return 0.3


# ── 4. MITRE ATT&CK FEED ─────────────────────────────────

def get_attck_score():
    """
    Counts MITRE ATT&CK techniques relevant to healthcare.
    No key needed — public GitHub data.
    Returns normalized 0.0 to 1.0.
    """
    try:
        url = ("https://raw.githubusercontent.com/mitre/cti"
               "/master/enterprise-attack/enterprise-attack.json")
        r    = requests.get(url, timeout=20, verify=False)
        objs = r.json().get("objects", [])

        healthcare_techs = [
            o for o in objs
            if o.get("type") == "attack-pattern"
            and any(
                kw in str(o).lower()
                for kw in ["health", "hospital", "medical",
                           "iot", "scada", "ics"]
            )
        ]
        score = round(min(1.0, len(healthcare_techs) / 50), 3)
        print(f"  [ATT&CK] {len(healthcare_techs)} healthcare techniques → {score}")
        return score
    except Exception as e:
        print(f"  [ATT&CK] Error: {e} — fallback 0.5")
        return 0.5


# ── COMBINED STATE FETCH ──────────────────────────────────

def get_live_threat_state():
    """
    Fetches all 4 threat scores.
    Called ONCE at environment startup — not every episode.
    """
    print("\n  [LTSA] Fetching live threat intelligence...")
    print("  " + "─" * 45)

    cve    = get_cve_score()
    shodan = get_shodan_score()
    abuse  = get_abuse_score()
    attck  = get_attck_score()

    level = "CRITICAL" if cve >= 0.9 else \
            "HIGH"     if cve >= 0.7 else \
            "MEDIUM"   if cve >= 0.5 else "LOW"

    print("  " + "─" * 45)
    print(f"  [LTSA] CVE score    : {cve}   → {level}")
    print(f"  [LTSA] Shodan score : {shodan}")
    print(f"  [LTSA] Abuse score  : {abuse}")
    print(f"  [LTSA] ATT&CK score : {attck}")
    print("  " + "─" * 45)

    return {
        "cve_score":    cve,
        "shodan_score": shodan,
        "abuse_score":  abuse,
        "attck_score":  attck
    }


# ── STANDALONE TEST ───────────────────────────────────────

if __name__ == "__main__":
    print("=" * 50)
    print("  GhostNet LTSA — Live Threat Feed Test")
    print("=" * 50)
    result = get_live_threat_state()
    print()
    print(f"  State index 5 (CVE)    = {result['cve_score']}")
    print(f"  State index 6 (Shodan) = {result['shodan_score']}")
    print(f"  State index 7 (Abuse)  = {result['abuse_score']}")
    print(f"  State index 8 (ATT&CK) = {result['attck_score']}")
    print()
    print("  All 4 scores flow into GhostNet RL state.")
    print("=" * 50)