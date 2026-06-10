"""
GhostNet Threat Feeds — Phase 2
================================
Connects to real-world threat intelligence APIs.
Injects live data into the RL agent's state vector.

APIs used:
- NIST NVD CVE API  : free, no key needed
- Shodan            : free academic key (optional)
"""

import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
import requests
import ssl
import certifi
from datetime import datetime, timedelta, timezone

# ─────────────────────────────────────────────
# CVE FEED — NIST National Vulnerability Database
# ─────────────────────────────────────────────

def get_cve_score():
    """
    Fetches CVEs published in the last 7 days from NIST NVD.
    Returns normalized score 0.0 (safe) to 1.0 (critical).
    Free — no API key needed.
    """
    end   = datetime.now(timezone.utc).replace(tzinfo=None)
    start = end - timedelta(days=7)
    url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    params = {
        "pubStartDate":  start.strftime("%Y-%m-%dT%H:%M:%S.000"),
        "pubEndDate":    end.strftime("%Y-%m-%dT%H:%M:%S.000"),
        "resultsPerPage": 20
    }

    try:
        r = requests.get(url, params=params, timeout=15, verify=False)
        r.raise_for_status()
        vulns = r.json().get("vulnerabilities", [])

        scores = []
        cve_ids = []
        for v in vulns:
            cve_id  = v["cve"].get("id", "unknown")
            metrics = v["cve"].get("metrics", {})
            if "cvssMetricV31" in metrics:
                s = metrics["cvssMetricV31"][0]["cvssData"]["baseScore"]
                scores.append(s)
                cve_ids.append((cve_id, s))
            elif "cvssMetricV30" in metrics:
                s = metrics["cvssMetricV30"][0]["cvssData"]["baseScore"]
                scores.append(s)
                cve_ids.append((cve_id, s))

        if scores:
            max_score = max(scores)
            normalized = round(max_score / 10.0, 3)
            # Show top 3 CVEs
            top3 = sorted(cve_ids, key=lambda x: x[1], reverse=True)[:3]
            print(f"  Live CVE feed: {len(scores)} CVEs this week")
            for cid, sc in top3:
                print(f"    {cid}  CVSS: {sc}")
            print(f"  Highest CVSS: {max_score}  →  Normalized: {normalized}")
            return normalized
        else:
            print("  No scored CVEs found — using default 0.3")
            return 0.3

    except requests.exceptions.Timeout:
        print("  CVE API timeout — fallback 0.3")
        return 0.3
    except Exception as e:
        print(f"  CVE API error: {e} — fallback 0.3")
        return 0.3


# ─────────────────────────────────────────────
# SHODAN FEED — internet exposure score (optional)
# ─────────────────────────────────────────────

def get_shodan_score(api_key=None):
    """
    Returns a simulated Shodan score if no API key provided.
    With a real Shodan academic key, queries real exposure data.
    """
    if api_key is None:
        # Simulated score — replace with real key later
        import random
        score = round(random.uniform(0.2, 0.7), 3)
        print(f"  Shodan: simulated score {score} (add API key for real data)")
        return score

    try:
        # Real Shodan query — requires academic API key
        url = f"https://api.shodan.io/shodan/host/count"
        params = {"key": api_key, "query": "hospital port:8080"}
        r = requests.get(url, params=params, timeout=10)
        count = r.json().get("total", 0)
        score = min(1.0, count / 10000)
        print(f"  Shodan: {count} exposed hospital services → score {score}")
        return score
    except Exception as e:
        print(f"  Shodan error: {e} — fallback 0.4")
        return 0.4


# ─────────────────────────────────────────────
# COMBINED STATE VECTOR UPDATE
# ─────────────────────────────────────────────

def get_live_threat_state():
    """
    Returns a partial state update from live threat feeds.
    Call this in GhostNetEnv.reset() to inject real data.
    """
    print("\n[LTSA] Fetching live threat intelligence...")
    cve   = get_cve_score()
    shodan = get_shodan_score()  # add your key here when you have it

    threat_level = "CRITICAL" if cve >= 0.9 else \
                   "HIGH"     if cve >= 0.7 else \
                   "MEDIUM"   if cve >= 0.5 else "LOW"

    print(f"\n[LTSA] Threat summary:")
    print(f"  CVE score    : {cve}  →  {threat_level}")
    print(f"  Shodan score : {shodan}")

    return {
        "cve_score":    cve,
        "shodan_score": shodan
    }


# ─────────────────────────────────────────────
# STANDALONE TEST
# ─────────────────────────────────────────────

if __name__ == "__main__":
    print("=" * 50)
    print("GhostNet LTSA — Live Threat Feed Test")
    print("=" * 50)

    result = get_live_threat_state()

    print("\n" + "=" * 50)
    print(f"State index 5 (CVE)    = {result['cve_score']}")
    print(f"State index 6 (Shodan) = {result['shodan_score']}")
    print("=" * 50)
    print("These values now flow into GhostNet's RL state.")
    print("The agent will mutate more aggressively when CVE is high.")
