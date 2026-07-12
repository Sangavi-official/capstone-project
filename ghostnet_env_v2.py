"""
GhostNet Environment v2 — Phase 2/3 (Corrected, Final)
=========================================================
Hospital IoT + cloud network simulator with live threat
intelligence properly integrated into a 12-dimension state
vector. No index is shared between two different signals.

STATE VECTOR (locked specification — see STATE_VECTOR_SPEC.txt):
  [0]  cloud_ip_exposure
  [1]  open_ports
  [2]  api_exposure
  [3]  iot_ip_exposure
  [4]  mqtt_exposure
  [5]  cve_score            (live, fetched once at construction)
  [6]  shodan_score         (live, fetched once at construction)
  [7]  traffic_load
  [8]  recon_attempts       (independent, no blending)
  [9]  time_since_mutation
  [10] abuse_score          (live, fetched once at construction)
  [11] attck_score          (live, fetched once at construction)

ACTION SPACE (6 mutations):
  0 = rotate_cloud_ip
  1 = close_open_port
  2 = rotate_api_path
  3 = rotate_iot_ip
  4 = rotate_mqtt_topic
  5 = update_firewall

REWARD — Traffic-Aware Dual-Objective Reward (TADR), with:
  - DESOLATER-inspired connection migration
    (Yoon et al., IEEE Access 2021, DOI:10.1109/ACCESS.2021.3076599)
  - LTSA-driven bonus for closing ports/API under high CVE threat
"""

import gymnasium as gym
import numpy as np
from threat_feeds import get_live_threat_state


class GhostNetEnvV2(gym.Env):

    STATE_DIM = 12

    def __init__(self, use_live_feeds=True):
        super().__init__()
        self.use_live_feeds = use_live_feeds

        self.observation_space = gym.spaces.Box(
            low=0, high=1, shape=(self.STATE_DIM,), dtype=np.float32
        )
        self.action_space = gym.spaces.Discrete(6)

        self.state        = None
        self.step_count   = 0
        self.mutation_log = []

        self.action_names = [
            "rotate_cloud_ip",   "close_open_port",
            "rotate_api_path",   "rotate_iot_ip",
            "rotate_mqtt_topic", "update_firewall"
        ]

        # Live threat scores fetched ONCE here, never in reset()/step().
        self.cached_cve    = 0.3
        self.cached_shodan = 0.4
        self.cached_abuse  = 0.3
        self.cached_attck  = 0.2

        if use_live_feeds:
            try:
                feeds = get_live_threat_state()
                self.cached_cve    = feeds["cve_score"]
                self.cached_shodan = feeds["shodan_score"]
                self.cached_abuse  = feeds["abuse_score"]
                self.cached_attck  = feeds["attck_score"]
            except Exception as e:
                print(f"  [ENV] Threat feed error — using defaults. {e}")

    def reset(self, seed=None):
        super().reset(seed=seed)

        self.state = np.random.uniform(0, 1, self.STATE_DIM).astype(np.float32)

        # Realistic baseline values
        self.state[7] = np.random.uniform(0.1, 0.5)   # traffic_load
        self.state[8] = np.random.uniform(0.0, 0.3)   # recon_attempts (pure)
        self.state[9] = 0.0                            # time_since_mutation

        # Live, independent threat scores
        self.state[5]  = self.cached_cve
        self.state[6]  = self.cached_shodan
        self.state[10] = self.cached_abuse
        self.state[11] = self.cached_attck

        self.step_count   = 0
        self.mutation_log = []

        return self.state, {}

    def step(self, action):
        self.step_count += 1
        new_state    = self.state.copy()
        traffic_load = float(new_state[7])

        # DESOLATER-inspired connection migration:
        # high traffic -> gentle mutation with handoff window,
        # low traffic  -> aggressive mutation is safe.
        if traffic_load > 0.5:
            new_state[action] = np.random.uniform(0.1, 0.25)
            connection_safe   = True
        else:
            new_state[action] = np.random.uniform(0.0, 0.15)
            connection_safe   = True

        attacker_disruption = 1.0 - new_state[action]
        traffic_penalty      = traffic_load * (0.05 if connection_safe else 0.2)
        mutation_cost         = 0.05

        # LTSA bonus: reward closing ports/API specifically when
        # live CVE threat is genuinely high.
        cve_bonus = 0.1 if (new_state[5] > 0.7 and action in [1, 2]) else 0.0

        # Additional LTSA bonus: reward firewall/firewall-adjacent
        # action when abuse_score is genuinely high (many active
        # malicious IPs reported right now).
        abuse_bonus = 0.05 if (new_state[10] > 0.7 and action in [1, 5]) else 0.0

        desolater_bonus = 0.05 if (traffic_load > 0.5 and connection_safe) else 0.0

        reward = (attacker_disruption
                  - traffic_penalty
                  - mutation_cost
                  + cve_bonus
                  + abuse_bonus
                  + desolater_bonus)

        self.mutation_log.append({
            "step":    self.step_count,
            "action":  self.action_names[action],
            "reward":  round(reward, 4),
            "cve":     round(float(new_state[5]), 3),
            "abuse":   round(float(new_state[10]), 3),
            "traffic": round(traffic_load, 3)
        })

        # recon_attempts increases independently over time —
        # no longer blended with any other signal.
        new_state[8] = min(1.0, new_state[8] + np.random.uniform(0, 0.03))
        new_state[9] = 0.0

        self.state = new_state
        done = self.step_count >= 200
        return self.state, reward, done, False, {}

    def render(self):
        labels = [
            "Cloud IP exposure   ", "Open ports          ",
            "API exposure        ", "IoT gateway IP      ",
            "MQTT exposure       ", "CVE score (live)    ",
            "Shodan score (live) ", "Traffic load        ",
            "Recon attempts      ", "Since last mutation ",
            "Abuse score (live)  ", "ATT&CK score (live) "
        ]
        print(f"\n  Step {self.step_count} — Hospital Network State:")
        print("  " + "-" * 58)
        for i, (label, val) in enumerate(zip(labels, self.state)):
            bar   = "#" * int(val * 20)
            level = "CRIT" if val > 0.8 else \
                    "HIGH" if val > 0.6 else \
                    "MED"  if val > 0.4 else "LOW"
            print(f"  [{i:>2}] {label}: {val:.3f} {bar:<20} {level}")
        print("  " + "-" * 58)
