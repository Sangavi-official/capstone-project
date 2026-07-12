"""
caldera_bridge.py — GhostNet Phase 5
=====================================
Connects to a locally-running CALDERA server via its REST API.
Creates a healthcare-specific adversary, starts an operation, and
continuously polls for executed TTPs (ATT&CK techniques).

Each TTP is mapped to one or more threat dimensions in GhostNet's
12-dim state vector, producing a "threat injection" dict that
phase5_eval.py overlays on top of the normal threat-feed values.

Usage (standalone test):
    python caldera_bridge.py

Usage (from eval):
    from caldera_bridge import CalderaBridge
    bridge = CalderaBridge()
    bridge.start_operation()
    injection = bridge.get_threat_injection()   # call each env step
    bridge.stop_operation()
"""

import time
import logging
import requests
from typing import Dict, Optional

# ── Config ────────────────────────────────────────────────────────────────────
CALDERA_URL   = "http://localhost:8888"
API_KEY       = "ADMIN123"          # default CALDERA dev key
OPERATION_NAME = "GhostNet-Phase5-Eval"

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [CALDERA] %(levelname)s: %(message)s"
)
log = logging.getLogger("caldera_bridge")

# ── TTP → GhostNet threat dimension mapping ──────────────────────────────────
# GhostNet 12-dim state (from ghostnet_env_v3.py):
#   0: cvss_score          (0-1)   — NIST CVE severity
#   1: abuseipdb_score     (0-1)   — IP reputation
#   2: attck_score         (0-1)   — MITRE ATT&CK match
#   3: port_exposure       (0-1)   — open port count / max
#   4: connection_rate     (0-1)   — connections per interval
#   5: mutation_count      (0-1)   — recent mutations (normalised)
#   6: time_since_mutation (0-1)   — staleness (1=never mutated)
#   7: threat_composite    (0-1)   — weighted aggregate
#   8: lateral_movement    (0-1)   — east-west traffic anomaly
#   9: data_exfil_risk     (0-1)   — egress volume anomaly
#  10: c2_likelihood       (0-1)   — C2 beacon pattern score
#  11: ransomware_risk     (0-1)   — encryption / write-spike indicator
#
# Each ATT&CK technique ID maps to {dimension_index: boost_value}.
# Boost values are ADDED to existing env threat scores (clamped to 1.0).

TTP_BOOST_MAP: Dict[str, Dict[int, float]] = {
    # Initial Access
    "T1190": {0: 0.4, 3: 0.5, 7: 0.3},   # Exploit Public-Facing Application
    "T1133": {3: 0.3, 4: 0.3, 7: 0.2},   # External Remote Services
    "T1078": {1: 0.3, 7: 0.2},            # Valid Accounts (credential abuse)

    # Discovery
    "T1046": {3: 0.6, 4: 0.5, 7: 0.3},   # Network Service Discovery (port scan)
    "T1082": {7: 0.2},                     # System Information Discovery
    "T1083": {9: 0.2, 7: 0.15},           # File & Directory Discovery

    # Lateral Movement
    "T1021": {8: 0.6, 4: 0.4, 7: 0.3},   # Remote Services (SSH/RDP)
    "T1563": {8: 0.5, 7: 0.25},           # Remote Service Session Hijacking

    # Command & Control
    "T1071": {10: 0.7, 4: 0.4, 7: 0.35}, # Application Layer Protocol (C2)
    "T1095": {10: 0.5, 4: 0.3, 7: 0.25}, # Non-Application Layer Protocol
    "T1572": {10: 0.6, 7: 0.3},           # Protocol Tunneling (DNS/HTTPS C2)

    # Exfiltration
    "T1041": {9: 0.7, 4: 0.5, 7: 0.4},   # Exfiltration Over C2 Channel
    "T1048": {9: 0.8, 3: 0.3, 7: 0.45},  # Exfil Over Alternative Protocol

    # Impact — highest priority for hospital context
    "T1486": {11: 0.9, 7: 0.6, 0: 0.5},  # Data Encrypted for Impact (RANSOMWARE)
    "T1489": {11: 0.7, 7: 0.5},           # Service Stop (disrupts infusion pump comms)
    "T1529": {11: 0.6, 7: 0.45},          # System Shutdown/Reboot
    "T1565": {11: 0.5, 9: 0.4, 7: 0.35}, # Data Manipulation (alter pump dosage data)
}

# Adversary definition — healthcare-targeted hospital ransomware kill-chain
HEALTHCARE_ADVERSARY = {
    "name": "Hospital-IoT-Ransomware",
    "description": (
        "Simulates the AIIMS Delhi 2022-style ransomware kill-chain targeting "
        "hospital IoT and cloud infrastructure. Maps to MITRE ATT&CK techniques "
        "observed in healthcare sector incidents."
    ),
    "atomic_ordering": [
        "T1046",  # scan for open ports / MQTT 1883
        "T1190",  # exploit public-facing EC2 / API
        "T1078",  # use stolen credentials
        "T1021",  # lateral movement via SSH
        "T1071",  # establish C2 channel
        "T1041",  # exfiltrate patient data
        "T1565",  # manipulate infusion pump telemetry
        "T1486",  # encrypt files (ransomware payload)
        "T1489",  # stop hospital services
    ],
    "tags": ["healthcare", "ransomware", "iot", "ghostnet-eval"],
}


class CalderaBridge:
    """
    Manages CALDERA lifecycle and provides threat injection data
    to GhostNet's evaluation environment.
    """

    def __init__(self, caldera_url: str = CALDERA_URL, api_key: str = API_KEY):
        self.base_url    = caldera_url.rstrip("/")
        self.headers     = {
            "KEY": api_key,
            "Content-Type": "application/json",
        }
        self.operation_id: Optional[str] = None
        self._active_ttps: Dict[str, float] = {}  # TTP_ID → activation_time
        self._injection_cache: Dict[int, float] = {}

        # Verify server is reachable
        self._verify_connection()

    # ── Connection ────────────────────────────────────────────────────────────

    def _verify_connection(self):
        try:
            r = requests.get(
                f"{self.base_url}/api/v2/operations",
                headers=self.headers,
                timeout=5
            )
            r.raise_for_status()
            log.info("CALDERA server reachable at %s", self.base_url)
        except Exception as e:
            raise ConnectionError(
                f"Cannot reach CALDERA at {self.base_url}. "
                f"Is Docker running? Error: {e}"
            )

    # ── Adversary setup ───────────────────────────────────────────────────────

    def _get_or_create_adversary(self) -> str:
        """Return adversary ID, creating if it doesn't exist."""
        r = requests.get(
            f"{self.base_url}/api/v2/adversaries",
            headers=self.headers
        )
        r.raise_for_status()
        for adv in r.json():
            if adv.get("name") == HEALTHCARE_ADVERSARY["name"]:
                log.info("Adversary already exists: %s", adv["adversary_id"])
                return adv["adversary_id"]

        # Create new adversary
        payload = {
            "name":        HEALTHCARE_ADVERSARY["name"],
            "description": HEALTHCARE_ADVERSARY["description"],
            "tags":        HEALTHCARE_ADVERSARY["tags"],
        }
        r = requests.post(
            f"{self.base_url}/api/v2/adversaries",
            headers=self.headers,
            json=payload
        )
        r.raise_for_status()
        adv_id = r.json()["adversary_id"]
        log.info("Created adversary: %s", adv_id)
        return adv_id

    # ── Operation lifecycle ───────────────────────────────────────────────────

    def start_operation(self) -> str:
        """Create and start a CALDERA operation. Returns operation ID."""
        adv_id = self._get_or_create_adversary()

        payload = {
            "name":      OPERATION_NAME,
            "adversary": {"adversary_id": adv_id},
            "planner":   {"id": "aaa7c857-37a0-4c4a-85f7-4e9f7f30e31a"},  # atomic
            "auto_close": False,
            "state":     "running",
        }
        r = requests.post(
            f"{self.base_url}/api/v2/operations",
            headers=self.headers,
            json=payload
        )
        r.raise_for_status()
        self.operation_id = r.json()["id"]
        log.info("Operation started: %s", self.operation_id)
        return self.operation_id

    def stop_operation(self):
        """Gracefully close the CALDERA operation."""
        if not self.operation_id:
            return
        r = requests.patch(
            f"{self.base_url}/api/v2/operations/{self.operation_id}",
            headers=self.headers,
            json={"state": "finished"}
        )
        r.raise_for_status()
        log.info("Operation closed: %s", self.operation_id)
        self.operation_id = None

    # ── TTP polling ───────────────────────────────────────────────────────────

    def _poll_executed_links(self) -> list:
        """Fetch all executed links (TTPs) from the running operation."""
        if not self.operation_id:
            return []
        try:
            r = requests.get(
                f"{self.base_url}/api/v2/operations/{self.operation_id}/links",
                headers=self.headers,
                timeout=5
            )
            r.raise_for_status()
            return r.json()
        except Exception as e:
            log.warning("Failed to poll CALDERA links: %s", e)
            return []

    def _inject_manual_ttp(self, ttp_id: str):
        """
        Manually inject a TTP activation (used in headless/no-agent mode
        where CALDERA cannot execute against real infrastructure).
        Simulates attack progression through the kill-chain.
        """
        if ttp_id not in self._active_ttps:
            self._active_ttps[ttp_id] = time.time()
            log.info("TTP activated (manual injection): %s", ttp_id)

    def simulate_attack_sequence(self, delay_seconds: float = 2.0):
        """
        Headless mode: replay the healthcare kill-chain with delays
        between each TTP — simulates a real attacker progression.
        Call this in a background thread during evaluation.
        """
        log.info("Starting simulated attack kill-chain (%d TTPs)",
                 len(HEALTHCARE_ADVERSARY["atomic_ordering"]))
        for ttp in HEALTHCARE_ADVERSARY["atomic_ordering"]:
            self._inject_manual_ttp(ttp)
            time.sleep(delay_seconds)
        log.info("Kill-chain simulation complete")

    # ── Threat injection ──────────────────────────────────────────────────────

    def get_threat_injection(self) -> Dict[int, float]:
        """
        Returns a dict {state_dimension_index: boost_value} representing
        the current attacker pressure. phase5_eval.py adds this to
        the environment's base observation before feeding it to the agent.

        Boosts decay over time (30s half-life) so a stale TTP loses impact,
        forcing the agent to keep mutating rather than settling.
        """
        # Poll real CALDERA links (works when sandcat agent is deployed)
        for link in self._poll_executed_links():
            ability = link.get("ability", {})
            ttp_id  = ability.get("technique_id", "")
            status  = link.get("status", -1)
            if status == 0 and ttp_id:  # 0 = success
                if ttp_id not in self._active_ttps:
                    self._active_ttps[ttp_id] = time.time()

        # Build injection vector with time-decay
        injection: Dict[int, float] = {}
        now = time.time()
        HALF_LIFE = 30.0  # seconds

        for ttp_id, activation_time in list(self._active_ttps.items()):
            elapsed = now - activation_time
            decay   = 0.5 ** (elapsed / HALF_LIFE)

            if decay < 0.05:  # TTP influence effectively zero
                del self._active_ttps[ttp_id]
                continue

            boosts = TTP_BOOST_MAP.get(ttp_id, {})
            for dim, base_boost in boosts.items():
                injection[dim] = min(1.0, injection.get(dim, 0.0) + base_boost * decay)

        self._injection_cache = injection
        return injection

    def get_active_ttp_count(self) -> int:
        return len(self._active_ttps)

    def get_active_ttps(self) -> list:
        return list(self._active_ttps.keys())

    def reset(self):
        """Clear all active TTPs (call between evaluation episodes)."""
        self._active_ttps.clear()
        self._injection_cache.clear()


# ── Standalone test ───────────────────────────────────────────────────────────

if __name__ == "__main__":
    import threading

    bridge = CalderaBridge()
    print("\n[TEST] Starting operation...")
    bridge.start_operation()

    print("[TEST] Injecting kill-chain in background (2s between TTPs)...")
    t = threading.Thread(target=bridge.simulate_attack_sequence, kwargs={"delay_seconds": 2.0})
    t.start()

    print("[TEST] Polling threat injection every 3s for 30s...\n")
    for _ in range(10):
        time.sleep(3)
        inj = bridge.get_threat_injection()
        ttps = bridge.get_active_ttps()
        print(f"  Active TTPs ({len(ttps)}): {ttps}")
        print(f"  Injection vector: { {k: round(v,3) for k,v in inj.items()} }\n")

    t.join()
    bridge.stop_operation()
    print("[TEST] Done.")
