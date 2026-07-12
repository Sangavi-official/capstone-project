"""
ghostnet_env_v3.py (Phase 4 update)
====================================
Extends the Phase 3 environment so actions 3 and 4 trigger real
SSH-based mutations on the virtual IoT device, alongside the
existing AWS mutations from cloud_mutator.py for actions 0, 1, 2, 5.

This is the dual-domain action space (DUAS) fully wired:
one agent, one decision, two real infrastructure domains.
"""

from ghostnet_env_v2 import GhostNetEnvV2
from p3_cloud_mutator import execute_mutation as execute_cloud_mutation
from p3_cloud_mutator import get_mutation_history as get_cloud_history
from iot_mutator import rotate_iot_topic, restart_broker_with_new_port
from iot_mutator import get_mutation_history as get_iot_history


class GhostNetEnvV3(GhostNetEnvV2):

    def __init__(self, use_live_feeds=True, use_real_cloud=True, use_real_iot=True):
        super().__init__(use_live_feeds=use_live_feeds)
        self.use_real_cloud = use_real_cloud
        self.use_real_iot = use_real_iot
        self.real_mutations = 0
        self.failed_mutations = 0
        print("  [V3] Real cloud mutations:", "ENABLED" if use_real_cloud else "DISABLED")
        print("  [V3] Real IoT mutations  :", "ENABLED" if use_real_iot else "DISABLED")

    def step(self, action):
        obs, reward, done, truncated, info = super().step(action)

        success = None
        if action == 3 and self.use_real_iot:
            success = restart_broker_with_new_port()
        elif action == 4 and self.use_real_iot:
            success = rotate_iot_topic()
        elif self.use_real_cloud:
            success = execute_cloud_mutation(action)

        if success is not None:
            if success:
                self.real_mutations += 1
                reward += 0.05
            else:
                self.failed_mutations += 1
                reward -= 0.02

        return obs, reward, done, truncated, info

    def get_cloud_stats(self):
        return {
            "real_mutations": self.real_mutations,
            "failed_mutations": self.failed_mutations,
            "cloud_log": get_cloud_history(),
            "iot_log": get_iot_history()
        }
