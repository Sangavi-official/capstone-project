"""Slice 4: trained PPO agent chooses the mutation.
   Placeholder mutation for now — swap in Sangavi's real function when Phase 4 lands."""
from stable_baselines3 import PPO
from ghostnet_env_v2 import GhostNetEnvV2

MODEL = "ghostnet_final_BACKUP"   # change to whichever wins the compare

def placeholder_mutation(action):
    # TEMP — becomes iot_mutator.rotate_topic() / port hop once they verify at target
    print(f"[AGENT] chose action {action} -> (real mutation fires here)")

def run(steps=10):
    env = GhostNetEnvV2(use_live_feeds=False)
    model = PPO.load(MODEL)
    obs, _ = env.reset()
    for _ in range(steps):
        action, _ = model.predict(obs, deterministic=True)
        placeholder_mutation(action)     # <-- the single line that becomes Sangavi's call
        obs, r, done, trunc, _ = env.step(action)
        if done or trunc:
            obs, _ = env.reset()

if __name__ == "__main__":
    run()