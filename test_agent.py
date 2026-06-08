from stable_baselines3 import PPO
from ghostnet_env import GhostNetEnv
import numpy as np

env = GhostNetEnv()
model = PPO.load("best_model/best_model")

obs, _ = env.reset()
total_reward = 0

action_names = [
    "Rotate Cloud IP",
    "Close Open Port",
    "Change API Endpoint",
    "Rotate IoT Gateway IP",
    "Change MQTT Topic",
    "Update Firewall Rules"
]

print("=" * 50)
print("GhostNet Agent — Live Defense Simulation")
print("=" * 50)

for step in range(20):
    action, _ = model.predict(obs)
    obs, reward, done, _, _ = env.step(action)
    total_reward += reward
    print(f"Step {step+1:2d} | Action: {action_names[action]:25s} | Reward: {reward:.3f}")
    if done:
        break

print("=" * 50)
print(f"Total reward over 20 steps: {total_reward:.3f}")
print("=" * 50)