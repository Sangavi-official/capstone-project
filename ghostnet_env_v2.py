"""
GhostNet Environment v2 — Phase 2
===================================
Upgraded environment with live CVE threat intelligence.
State index 5 now uses real NIST CVE data instead of random values.
This is LTSA (Live Threat-Feed State Augmentation) implemented.
"""

import gymnasium as gym
import numpy as np
from threat_feeds import get_cve_score, get_shodan_score


class GhostNetEnvV2(gym.Env):

    def __init__(self, use_live_feeds=True):
        super().__init__()
        self.use_live_feeds = use_live_feeds

        self.observation_space = gym.spaces.Box(
            low=0, high=1, shape=(10,), dtype=np.float32
        )
        self.action_space = gym.spaces.Discrete(6)

        self.state = None
        self.step_count = 0
        self.mutation_log = []

        self.action_names = [
            "rotate_cloud_ip",
            "close_open_port",
            "rotate_api_path",
            "rotate_iot_ip",
            "rotate_mqtt_topic",
            "update_firewall"
        ]

    def reset(self, seed=None):
        super().reset(seed=seed)
        self.state = np.random.uniform(0, 1, 10).astype(np.float32)
        self.state[7] = np.random.uniform(0.1, 0.5)  # realistic traffic
        self.step_count = 0
        self.mutation_log = []

        # LTSA — inject live threat intelligence
        if self.use_live_feeds:
            try:
                self.state[5] = get_cve_score()      # real CVE score
                self.state[6] = get_shodan_score()    # real Shodan score
            except Exception:
                pass  # fallback to random if API unreachable

        return self.state, {}

    def step(self, action):
        self.step_count += 1
        new_state = self.state.copy()

        # Apply mutation
        new_state[action] = np.random.uniform(0.0, 0.2)

        # TADR reward
        attacker_disruption = 1.0 - new_state[action]
        traffic_penalty     = new_state[7] * 0.2

        # Bonus: extra reward if CVE is high and we mutate the right surface
        cve_bonus = 0.0
        if new_state[5] > 0.7 and action in [1, 2]:  # high CVE → close ports/API
            cve_bonus = 0.1

        mutation_cost = 0.05
        reward = attacker_disruption - traffic_penalty - mutation_cost + cve_bonus

        # Log this mutation
        self.mutation_log.append({
            "step":   self.step_count,
            "action": self.action_names[action],
            "reward": round(reward, 4),
            "cve":    round(float(new_state[5]), 3)
        })

        new_state[8] = min(1.0, new_state[8] + np.random.uniform(0, 0.05))
        new_state[9] = 0.0
        self.state = new_state

        done = self.step_count >= 200
        return self.state, reward, done, False, {}

    def render(self):
        print(f"\nStep {self.step_count} | Hospital Network State:")
        labels = [
            "Cloud IP exposure  ", "Open ports         ",
            "API exposure       ", "IoT gateway IP     ",
            "MQTT exposure      ", "CVE threat score   ",
            "Shodan score       ", "Traffic load       ",
            "Recon attempts     ", "Since last mutation"
        ]
        for i, (label, val) in enumerate(zip(labels, self.state)):
            bar   = "█" * int(val * 20)
            level = "CRITICAL" if val > 0.8 else "HIGH" if val > 0.6 else \
                    "MED"      if val > 0.4 else "LOW"
            print(f"  [{i}] {label}: {val:.3f} {bar:<20} {level}")
