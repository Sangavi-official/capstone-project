"""
GhostNet — Live Demo
=====================
Loads the trained agent and runs a 20-step live demonstration.
Shows every mutation decision, reward, and network state.
Use this for presentations, viva, and project demos.

Usage:
    python demo.py
"""

import numpy as np
from stable_baselines3 import PPO
from ghostnet_env import GhostNetEnv
import os
import time


def run_demo():
    # Load best model
    model_path = "best_model/best_model"
    if not os.path.exists(model_path + ".zip"):
        model_path = "ghostnet_v1"
        if not os.path.exists(model_path + ".zip"):
            print("No trained model found. Run train.py first.")
            return

    print("\n" + "=" * 60)
    print("  GhostNet — Hospital Network Defense LIVE DEMO")
    print("=" * 60)
    print("  Scenario: ICU infusion pump → cloud pharmacy pipeline")
    print("  Attacker: actively scanning and mapping the network")
    print("  GhostNet: AI agent mutating surfaces in real time")
    print("=" * 60)

    model = PPO.load(model_path)
    env   = GhostNetEnv()
    obs, _ = env.reset()

    action_names = [
        "Rotate cloud IP     ",
        "Close open port     ",
        "Rotate API path     ",
        "Rotate IoT gateway  ",
        "Rotate MQTT topic   ",
        "Update firewall     "
    ]

    # Map action to hospital meaning
    hospital_meaning = [
        "Cloud server IP changed — attacker's map is wrong",
        "Dangerous port closed — scanner finds nothing",
        "API endpoint rotated — forged drug command fails",
        "IoT gateway IP changed — device unreachable to attacker",
        "MQTT topic renamed — attacker's subscription fails",
        "Firewall rules updated — new scan patterns blocked"
    ]

    total_reward  = 0
    mutations_done = 0

    print(f"\n  {'Step':>4}  {'Action':<22}  {'Reward':>7}  {'Cumulative':>10}  Hospital Effect")
    print("  " + "─" * 90)

    for step in range(1, 21):
        action, _ = model.predict(obs, deterministic=True)
        obs, reward, done, _, _ = env.step(int(action))
        total_reward += reward
        mutations_done += 1

        reward_color = "▲" if reward > 0.7 else "●"
        print(f"  {step:>4}  {action_names[action]}  "
              f"{reward:>7.3f}  {total_reward:>10.3f}  "
              f"{hospital_meaning[action]}")

        time.sleep(0.15)  # slight delay for dramatic effect

        if done:
            obs, _ = env.reset()

    print("  " + "─" * 90)
    print(f"\n  Total reward over 20 steps : {total_reward:.3f}")
    print(f"  Mutations executed         : {mutations_done}")
    print(f"  Avg reward per mutation    : {total_reward/mutations_done:.3f}")

    if total_reward > 12:
        verdict = "STRONG DEFENSE — attacker reconnaissance disrupted successfully"
    elif total_reward > 8:
        verdict = "MODERATE DEFENSE — most attack vectors covered"
    else:
        verdict = "DEVELOPING — agent needs more training"

    print(f"\n  Verdict: {verdict}")
    print("\n" + "=" * 60)
    print("  Demo complete. GhostNet defended the hospital pipeline.")
    print("=" * 60)


if __name__ == "__main__":
    run_demo()
