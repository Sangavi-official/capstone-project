"""
phase5_eval.py — GhostNet Phase 5: Adversarial Evaluation
==========================================================
Works with YOUR existing codebase:
  - ghostnet_env_v3.py  (GhostNetEnvV3)
  - ghostnet_env_v2.py  (GhostNetEnvV2)
  - p3_cloud_mutator.py
  - iot_mutator.py
  - threat_feeds.py

Runs 3 scenarios × 10 episodes and saves phase5_results.json.

Run:
    python phase5_eval.py
"""

import json
import time
import threading
import numpy as np
from pathlib import Path
from stable_baselines3 import PPO
from caldera_bridge import CalderaBridge

# ── Config ────────────────────────────────────────────────────────────────────
MODEL_PATH   = "best_model/best_model.zip"
NUM_EPISODES = 10
MAX_STEPS    = 200
RESULTS_FILE = "phase5_results.json"
TTP_INTERVAL = 5.0   # seconds between each kill-chain stage


# ── Load environment ──────────────────────────────────────────────────────────

def make_env():
    """
    Load GhostNetEnvV3 — your actual production environment.
    use_real_iot=False  → skips SSH to EC2 during eval (safe for Phase 5)
    use_real_cloud=True → real AWS SG mutations still happen via boto3
    Set use_real_cloud=False if you want a fully offline eval run.
    """
    from ghostnet_env_v3 import GhostNetEnvV3
    print("[ENV] Loading GhostNetEnvV3...")
    env = GhostNetEnvV3(
        use_live_feeds=True,   # NIST / Shodan / AbuseIPDB / ATT&CK still active
        use_real_cloud=True,   # Real AWS SG mutations
        use_real_iot=False     # Skip SSH IoT mutations (EC2 SSH not needed for eval)
    )
    print("[ENV] GhostNetEnvV3 ready")
    return env


# ── Apply CALDERA threat injection to observation ─────────────────────────────

def apply_injection(obs: np.ndarray, injection: dict) -> np.ndarray:
    """
    Overlay CALDERA attack boosts onto the raw environment observation.
    Each active TTP boosts specific threat dimensions in the 12-dim state.
    """
    obs_copy = obs.copy().astype(np.float32)
    for dim_idx, boost in injection.items():
        if dim_idx < len(obs_copy):
            obs_copy[dim_idx] = min(1.0, float(obs_copy[dim_idx]) + boost)
    return obs_copy


# ── Run one scenario ──────────────────────────────────────────────────────────

def run_scenario(name, env, model, bridge, attack_active, num_ep, max_steps):
    print(f"\n{'='*50}")
    print(f"SCENARIO: {name.upper()} | attack={attack_active}")
    print(f"{'='*50}")

    all_episodes = []

    for ep in range(num_ep):
        obs, _ = env.reset()
        bridge.reset()

        # Start CALDERA kill-chain in background thread
        attack_thread = None
        if attack_active:
            attack_thread = threading.Thread(
                target=bridge.simulate_attack_sequence,
                kwargs={"delay_seconds": TTP_INTERVAL},
                daemon=True
            )
            attack_thread.start()

        ep_reward   = 0.0
        step_log    = []
        ttp_seen    = set()
        mutation_ct = 0

        for step in range(max_steps):
            injection = bridge.get_threat_injection() if attack_active else {}
            ttp_seen.update(bridge.get_active_ttps())

            obs_injected = apply_injection(obs, injection)

            if model is not None:
                action, _ = model.predict(obs_injected, deterministic=True)
            else:
                action = np.array([0])   # static: do nothing

            if int(action) != 0:
                mutation_ct += 1

            obs, reward, terminated, truncated, info = env.step(action)
            ep_reward += float(reward)

            step_log.append({
                "step":        step,
                "reward":      float(reward),
                "action":      int(action),
                "injection":   {str(k): round(float(v), 3) for k, v in injection.items()},
                "active_ttps": bridge.get_active_ttps(),
                "obs":         obs_injected.tolist(),
            })

            if terminated or truncated:
                break

        if attack_thread:
            attack_thread.join(timeout=5.0)

        ep_data = {
            "episode":        ep,
            "episode_reward": ep_reward,
            "steps":          len(step_log),
            "mutations":      mutation_ct,
            "ttp_sequence":   list(ttp_seen),
            "step_log":       step_log,
        }
        all_episodes.append(ep_data)
        print(f"  Episode {ep+1:2d}/{num_ep} → reward={ep_reward:7.2f} | "
              f"mutations={mutation_ct} | TTPs={len(ttp_seen)}")

    return all_episodes


# ── Summary stats ─────────────────────────────────────────────────────────────

def summarize(episodes):
    rewards   = [e["episode_reward"] for e in episodes]
    mutations = [e["mutations"] for e in episodes]

    # Attack success = fraction of steps where ransomware dim (11) > 0.5
    high_risk = total = 0
    mttd_list = []
    for ep in episodes:
        for s in ep["step_log"]:
            total += 1
            if len(s["obs"]) > 11 and s["obs"][11] > 0.5:
                high_risk += 1
        # MTTD: first step where agent mutated AND attack was active
        for s in ep["step_log"]:
            if s["action"] != 0 and len(s["active_ttps"]) > 0:
                mttd_list.append(s["step"])
                break

    return {
        "mean_reward":         round(float(np.mean(rewards)), 2),
        "std_reward":          round(float(np.std(rewards)), 2),
        "mean_mutations":      round(float(np.mean(mutations)), 1),
        "attack_success_rate": round(high_risk / max(total, 1), 4),
        "mttd_mean_steps":     round(float(np.mean(mttd_list)), 1) if mttd_list else None,
    }


# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    print("\nGhostNet Phase 5 — Adversarial Evaluation")
    print(f"Model: {MODEL_PATH}  |  Episodes: {NUM_EPISODES}  |  Steps: {MAX_STEPS}\n")

    # Load model
    model_path = Path(MODEL_PATH)
    if not model_path.exists():
        model_path = Path("ghostnet_final.zip")
    if not model_path.exists():
        raise FileNotFoundError(
            "Trained model not found. Expected: best_model/best_model.zip "
            "or ghostnet_final.zip"
        )
    model = PPO.load(str(model_path))
    print(f"[MODEL] Loaded: {model_path}")

    # Connect to CALDERA
    bridge = CalderaBridge()
    bridge.start_operation()

    # Create environment
    env = make_env()

    results = {}
    try:
        # Scenario 1: Agent, no attack
        eps = run_scenario("baseline", env, model, bridge,
                           attack_active=False,
                           num_ep=NUM_EPISODES, max_steps=MAX_STEPS)
        results["baseline"] = {"episodes": eps, "summary": summarize(eps)}

        # Scenario 2: Agent + CALDERA attack  ← KEY RESULT
        eps = run_scenario("under_attack", env, model, bridge,
                           attack_active=True,
                           num_ep=NUM_EPISODES, max_steps=MAX_STEPS)
        results["under_attack"] = {"episodes": eps, "summary": summarize(eps)}

        # Scenario 3: Static (no agent) + CALDERA attack  ← comparison
        eps = run_scenario("static_defense", env, model=None, bridge=bridge,
                           attack_active=True,
                           num_ep=NUM_EPISODES, max_steps=MAX_STEPS)
        results["static_defense"] = {"episodes": eps, "summary": summarize(eps)}

    finally:
        env.close()
        bridge.stop_operation()

    # Save results
    with open(RESULTS_FILE, "w") as f:
        json.dump(results, f, indent=2)
    print(f"\n[DONE] Results saved → {RESULTS_FILE}")

    # Print summary
    print("\n" + "="*55)
    print("PHASE 5 RESULTS SUMMARY")
    print("="*55)
    for scenario, data in results.items():
        s = data["summary"]
        print(f"\n[{scenario.upper()}]")
        print(f"  Mean Reward       : {s['mean_reward']} ± {s['std_reward']}")
        print(f"  Mean Mutations/ep : {s['mean_mutations']}")
        print(f"  Attack Success    : {s['attack_success_rate']*100:.1f}%")
        print(f"  MTTD (steps)      : {s['mttd_mean_steps']}")
    print("="*55)
    print("\nNext → run: python phase5_visualize.py")


if __name__ == "__main__":
    main()
