"""
GhostNet Environment — Phase 1
================================
Simulates a hospital IoT + cloud network as an RL environment.
State: 10 values representing exposure levels of hospital systems.
Actions: 6 mutations the agent can apply to reduce attack surface.
Reward: TADR formula — attacker disruption minus traffic penalty.
"""

import gymnasium as gym
import numpy as np


class GhostNetEnv(gym.Env):

    def __init__(self):
        super().__init__()

        # --------------------------------------------------
        # STATE SPACE — 10 values, each between 0.0 and 1.0
        # 0 = safe/hidden    1 = fully exposed/dangerous
        # --------------------------------------------------
        # Index 0 : cloud_ip_exposure      — how visible the cloud server IP is
        # Index 1 : open_ports             — how many ports are open
        # Index 2 : api_exposure           — how exposed the REST API endpoints are
        # Index 3 : iot_ip_exposure        — how visible the IoT gateway IP is
        # Index 4 : mqtt_exposure          — how exposed MQTT topics are
        # Index 5 : cve_score              — live CVE threat score (Phase 2: real data)
        # Index 6 : shodan_score           — Shodan internet exposure score
        # Index 7 : traffic_load           — current legitimate hospital traffic
        # Index 8 : recon_attempts         — attacker scan frequency detected
        # Index 9 : time_since_mutation    — how long since last mutation
        # --------------------------------------------------
        self.observation_space = gym.spaces.Box(
            low=0, high=1, shape=(10,), dtype=np.float32
        )

        # --------------------------------------------------
        # ACTION SPACE — 6 possible mutations
        # --------------------------------------------------
        # Action 0 : rotate_cloud_ip       — change cloud server IP address
        # Action 1 : close_open_port       — close an exposed port
        # Action 2 : rotate_api_path       — change REST API endpoint URLs
        # Action 3 : rotate_iot_ip         — change IoT gateway IP address
        # Action 4 : rotate_mqtt_topic     — change MQTT topic namespace
        # Action 5 : update_firewall       — update firewall rules
        # --------------------------------------------------
        self.action_space = gym.spaces.Discrete(6)

        self.state = None
        self.step_count = 0
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
        # Random initial state — simulates hospital network at start of episode
        self.state = np.random.uniform(0, 1, 10).astype(np.float32)
        # Traffic load stays moderate (hospital always has some traffic)
        self.state[7] = np.random.uniform(0.1, 0.5)
        self.step_count = 0
        return self.state, {}

    def step(self, action):
        self.step_count += 1
        new_state = self.state.copy()

        # Apply mutation — reduce exposure on the targeted surface
        new_state[action] = np.random.uniform(0.0, 0.2)

        # TADR reward formula:
        # R = attacker_disruption - traffic_penalty - mutation_cost
        attacker_disruption = 1.0 - new_state[action]   # how much we confused attacker
        traffic_penalty     = new_state[7] * 0.2         # disruption to real users
        mutation_cost       = 0.05                        # cost of any mutation

        reward = attacker_disruption - traffic_penalty - mutation_cost

        # Recon attempts increase over time if we don't mutate
        new_state[8] = min(1.0, new_state[8] + np.random.uniform(0, 0.05))
        # Time since mutation resets
        new_state[9] = 0.0

        self.state = new_state
        done = self.step_count >= 200

        return self.state, reward, done, False, {}

    def render(self):
        print(f"\nStep {self.step_count} | Hospital Network State:")
        labels = [
            "Cloud IP exposure  ",
            "Open ports         ",
            "API exposure       ",
            "IoT gateway IP     ",
            "MQTT exposure      ",
            "CVE threat score   ",
            "Shodan score       ",
            "Traffic load       ",
            "Recon attempts     ",
            "Since last mutation",
        ]
        for i, (label, val) in enumerate(zip(labels, self.state)):
            bar = "█" * int(val * 20)
            level = "CRITICAL" if val > 0.8 else "HIGH" if val > 0.6 else "MED" if val > 0.4 else "LOW"
            print(f"  [{i}] {label}: {val:.3f} {bar:<20} {level}")
