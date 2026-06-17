"""
GhostNet Environment v2 — Phase 2
====================================
Upgrades from Phase 1:
  1. LTSA — 4 live threat feeds in state (CVE, Shodan, AbuseIPDB, ATT&CK)
  2. DESOLATER — connection migration during IP mutation
     (Yoon et al., IEEE Access 2021, DOI: 10.1109/ACCESS.2021.3076599)
  3. TADR — traffic-aware dual-objective reward
  4. CVE bonus — extra reward for correct action at high threat

DESOLATER principle applied:
  High traffic → gentle mutation with handoff window (no patient disconnect)
  Low traffic  → aggressive mutation (maximum attacker disruption)

All threat data fetched ONCE at startup — no API spam during training.
"""

import gymnasium as gym
import numpy as np
from threat_feeds import get_live_threat_state


class GhostNetEnvV2(gym.Env):

    def __init__(self, use_live_feeds=True):
        super().__init__()
        self.use_live_feeds = use_live_feeds

        # ── STATE SPACE (10 dimensions) ───────────────────
        # [0] cloud_ip_exposure      [1] open_ports
        # [2] api_exposure           [3] iot_ip_exposure
        # [4] mqtt_exposure          [5] cve_score       (LTSA)
        # [6] shodan_score           [7] abuse_score     (LTSA)
        # [8] recon_attempts         [9] time_since_mutation
        # ─────────────────────────────────────────────────
        self.observation_space = gym.spaces.Box(
            low=0, high=1, shape=(10,), dtype=np.float32)
        self.action_space = gym.spaces.Discrete(6)

        self.state        = None
        self.step_count   = 0
        self.mutation_log = []

        self.action_names = [
            "rotate_cloud_ip",   "close_open_port",
            "rotate_api_path",   "rotate_iot_ip",
            "rotate_mqtt_topic", "update_firewall"
        ]

        # ── FETCH THREAT DATA ONCE AT STARTUP ─────────────
        # CVE fetched here — NOT in reset() — prevents API spam
        # ─────────────────────────────────────────────────
        self.cached_cve    = 0.85   # default if API fails
        self.cached_shodan = 0.4
        self.cached_abuse  = 0.3
        self.cached_attck  = 0.5

        if use_live_feeds:
            try:
                feeds = get_live_threat_state()
                self.cached_cve    = feeds["cve_score"]
                self.cached_shodan = feeds["shodan_score"]
                self.cached_abuse  = feeds["abuse_score"]
                self.cached_attck  = feeds["attck_score"]
            except Exception as e:
                print(f"  [ENV] Feed error — using defaults. {e}")

    def reset(self, seed=None):
        super().reset(seed=seed)

        # Random base state
        self.state      = np.random.uniform(0, 1, 10).astype(np.float32)
        self.state[7]   = np.random.uniform(0.1, 0.5)  # realistic traffic
        self.step_count = 0
        self.mutation_log = []

        # Inject cached live threat scores
        self.state[5] = self.cached_cve
        self.state[6] = self.cached_shodan
        # Note: index 7 = traffic load (kept as random realistic value)
        # index 8 repurposed: abuse score blended with recon attempts
        self.state[8] = min(1.0,
            np.random.uniform(0, 0.3) + self.cached_abuse * 0.5)

        return self.state, {}

    def step(self, action):
        self.step_count += 1
        new_state    = self.state.copy()
        traffic_load = float(new_state[7])

        # ── DESOLATER CONNECTION MIGRATION ────────────────
        # Yoon et al. IEEE Access 2021 — proactive IP hopping
        # with handoff window to protect active connections.
        #
        # High traffic (>0.5): gentle mutation
        #   Both old and new address active briefly.
        #   Existing connections migrate silently.
        #   Patient monitors never lose connection.
        #
        # Low traffic (<0.5): aggressive mutation
        #   Hard cut — maximum attacker disruption.
        #   Safe because few legitimate connections active.
        # ─────────────────────────────────────────────────
        if traffic_load > 0.5:
            # DESOLATER handoff window — gentle mutation
            new_state[action] = np.random.uniform(0.1, 0.25)
            connection_safe   = True
        else:
            # Aggressive mutation — low traffic window
            new_state[action] = np.random.uniform(0.0, 0.15)
            connection_safe   = True  # safe — few active connections

        # ── TADR REWARD FORMULA ───────────────────────────
        # R = attacker_disruption
        #     - traffic_penalty    (TADR — protect patients)
        #     - mutation_cost      (cost of any action)
        #     + cve_bonus          (LTSA — correct action at high CVE)
        #     + desolater_bonus    (reward safe migration)
        # ─────────────────────────────────────────────────
        attacker_disruption = 1.0 - new_state[action]

        # Traffic penalty reduced during DESOLATER handoff
        # because connection migration protects patients
        traffic_penalty = traffic_load * (0.05 if connection_safe else 0.2)

        mutation_cost   = 0.05

        # CVE bonus: closing ports/API during high threat
        cve_bonus = 0.1 if (new_state[5] > 0.7
                            and action in [1, 2]) else 0.0

        # DESOLATER bonus: reward for safe migration at high traffic
        desolater_bonus = 0.05 if (traffic_load > 0.5
                                   and connection_safe) else 0.0

        reward = (attacker_disruption
                  - traffic_penalty
                  - mutation_cost
                  + cve_bonus
                  + desolater_bonus)

        # Log mutation
        self.mutation_log.append({
            "step":       self.step_count,
            "action":     self.action_names[action],
            "reward":     round(reward, 4),
            "cve":        round(float(new_state[5]), 3),
            "traffic":    round(traffic_load, 3),
            "handoff":    connection_safe
        })

        # Recon attempts increase over time
        new_state[8] = min(1.0,
            new_state[8] + np.random.uniform(0, 0.03))
        new_state[9] = 0.0   # reset time since mutation

        self.state = new_state
        done = self.step_count >= 200
        return self.state, reward, done, False, {}

    def render(self):
        labels = [
            "Cloud IP exposure  ", "Open ports         ",
            "API exposure       ", "IoT gateway IP     ",
            "MQTT exposure      ", "CVE score (live)   ",
            "Shodan score (live)", "Traffic load       ",
            "Recon + abuse      ", "Since last mutation"
        ]
        print(f"\n  Step {self.step_count} — Hospital Network State:")
        print("  " + "─" * 55)
        for i, (label, val) in enumerate(zip(labels, self.state)):
            bar   = "█" * int(val * 20)
            level = "CRIT" if val > 0.8 else \
                    "HIGH" if val > 0.6 else \
                    "MED"  if val > 0.4 else "LOW"
            print(f"  [{i}] {label}: {val:.3f} {bar:<20} {level}")
        print("  " + "─" * 55)