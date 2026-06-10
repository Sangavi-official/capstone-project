"""
GhostNet Training Script — Phase 1 + Phase 2
==============================================
Trains the PPO agent on the GhostNet environment.
Run this after ghostnet_env.py and threat_feeds.py are ready.

Usage:
    python train.py           # trains with live CVE data (Phase 2)
    python train.py --sim     # trains with simulated data only (Phase 1)
"""

import os
import sys
import argparse
from stable_baselines3 import PPO
from stable_baselines3.common.callbacks import EvalCallback
from stable_baselines3.common.monitor import Monitor

# Parse argument
parser = argparse.ArgumentParser()
parser.add_argument("--sim", action="store_true",
                    help="Use simulated data only (no live CVE calls)")
args = parser.parse_args()

use_live = not args.sim

# Import correct environment
if use_live:
    from ghostnet_env_v2 import GhostNetEnvV2 as EnvClass
    version = "v2 (LTSA — live CVE data)"
else:
    from ghostnet_env import GhostNetEnv as EnvClass
    version = "v1 (simulated data)"

print("=" * 55)
print("  GhostNet — Hospital Network Moving Target Defense")
print("=" * 55)
print(f"  Environment : {version}")
print(f"  Algorithm   : PPO (Proximal Policy Optimization)")
print(f"  Steps       : 100,000")
print("=" * 55)

# Create folders
os.makedirs("logs",       exist_ok=True)
os.makedirs("best_model", exist_ok=True)

# Create environments
env      = Monitor(EnvClass(use_live_feeds=use_live) if use_live else EnvClass(), "logs/")
eval_env = Monitor(EnvClass(use_live_feeds=False)    if use_live else EnvClass())

# Evaluation callback
eval_cb = EvalCallback(
    eval_env,
    best_model_save_path="./best_model/",
    log_path="./logs/",
    eval_freq=5000,
    n_eval_episodes=10,
    verbose=1
)

# PPO agent
model = PPO(
    "MlpPolicy", env,
    verbose=1,
    learning_rate=3e-4,
    n_steps=2048,
    batch_size=64,
    gamma=0.99,
    ent_coef=0.01
)

print("\n  Training started. Watch ep_rew_mean increase.\n")

model.learn(total_timesteps=100_000, callback=eval_cb)
model.save("ghostnet_v2" if use_live else "ghostnet_v1")

print("\n" + "=" * 55)
print(f"  Training complete.")
print(f"  Saved : ghostnet_{'v2' if use_live else 'v1'}.zip")
print(f"  Best  : best_model/best_model.zip")
print("=" * 55)
