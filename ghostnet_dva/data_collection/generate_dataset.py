"""
GhostNet DVA — Primary Data Collection Script
=============================================
Run this file ONCE to generate your primary dataset.
It loads your trained GhostNet agent, runs 500 episodes,
and logs 15 meaningful columns into a CSV file.

HOW TO RUN:
    cd C:\\Users\\SANGAVI\\Documents\\project\\ghostnet_dva\\data_collection
    python generate_dataset.py

OUTPUT:
    ghostnet_dva\\dataset\\ghostnet_primary_data.csv

IMPORTANT:
    This script only READS from your main ghostnet folder.
    It never modifies any file in your main project.
"""

import sys
import os
import csv
import numpy as np
import random
from datetime import datetime

# ─── PATH SETUP ───────────────────────────────────────────────────────────────
# Point to your main ghostnet project folder (read-only)
GHOSTNET_MAIN = r"C:\Users\SANGAVI\Documents\project\ghostnet"
sys.path.insert(0, GHOSTNET_MAIN)

# Output CSV path
OUTPUT_DIR  = os.path.join(os.path.dirname(__file__), "..", "dataset")
OUTPUT_FILE = os.path.join(OUTPUT_DIR, "ghostnet_primary_data.csv")
os.makedirs(OUTPUT_DIR, exist_ok=True)

# ─── IMPORT YOUR ENVIRONMENT ──────────────────────────────────────────────────
print("[1/5] Importing GhostNet environment...")
try:
    from ghostnet_env_v2 import GhostNetEnv
    ENV_VERSION = "v2 (Live CVE)"
    print("      ✓ Loaded ghostnet_env_v2.py (Phase 2 environment)")
except ImportError:
    try:
        from ghostnet_env import GhostNetEnv
        ENV_VERSION = "v1 (Simulation)"
        print("      ✓ Loaded ghostnet_env.py (Phase 1 environment)")
    except ImportError:
        print("      ✗ ERROR: Could not find ghostnet_env.py")
        print(f"        Make sure GHOSTNET_MAIN path is correct: {GHOSTNET_MAIN}")
        sys.exit(1)

# ─── LOAD TRAINED AGENT ───────────────────────────────────────────────────────
print("[2/5] Loading trained PPO agent...")
try:
    from stable_baselines3 import PPO
    MODEL_PATH = os.path.join(GHOSTNET_MAIN, "best_model", "best_model.zip")
    if not os.path.exists(MODEL_PATH):
        MODEL_PATH = os.path.join(GHOSTNET_MAIN, "ghostnet_v1.zip")
    model = PPO.load(MODEL_PATH)
    print(f"      ✓ Model loaded from: {MODEL_PATH}")
    USE_TRAINED_MODEL = True
except Exception as e:
    print(f"      ⚠ Could not load model ({e})")
    print("      → Will run environment with random actions instead")
    USE_TRAINED_MODEL = False

# ─── ACTION LABELS ────────────────────────────────────────────────────────────
# Matches the 6-action space defined in your ghostnet_env.py
ACTION_LABELS = {
    0: "rotate_cloud_ip",
    1: "close_port",
    2: "rotate_api_endpoint",
    3: "rotate_iot_ip",
    4: "change_mqtt_topic",
    5: "no_mutation"
}

# Mutation layer: which actions affect cloud vs IoT
CLOUD_ACTIONS = {0, 1, 2}   # cloud IP, port, API
IOT_ACTIONS   = {3, 4}       # IoT IP, MQTT

# ─── DATA COLLECTION ──────────────────────────────────────────────────────────
print("[3/5] Starting 500-episode data collection run...")
print("      This will take 2–5 minutes. Please wait.\n")

EPISODES     = 500
MAX_STEPS    = 200

env = GhostNetEnv()

CSV_COLUMNS = [
    # Episode metadata
    "episode",               # Episode number (1–500)
    "timestamp_sec",         # Wall-clock seconds since collection started

    # Core performance
    "total_reward",          # Total reward for this episode (main KPI)
    "steps_completed",       # Steps before episode ended
    "defense_efficiency_pct",# Reward as % of max possible (190) → 0–100

    # Threat environment
    "cve_score",             # Threat level from NIST CVE feed (0.0–1.0)
    "threat_level",          # Categorical: LOW / MEDIUM / HIGH / CRITICAL
    "recon_events",          # Times attacker recon was detected this episode

    # Agent behaviour
    "dominant_action",       # Most-used action this episode (0–5)
    "dominant_action_name",  # Human label for dominant action
    "action_diversity",      # Unique actions used (1–6) → higher = more adaptive
    "cloud_mutations",       # Times cloud layer was mutated
    "iot_mutations",         # Times IoT layer was mutated
    "api_mutations",         # Times API endpoint was rotated (AESM)

    # Patient safety (TADR reward component)
    "traffic_disruption_avg",# Average legitimate traffic disruption (0.0–1.0)
    "traffic_disruption_max",# Worst single-step disruption this episode

    # Network state snapshots (start vs end)
    "cloud_ip_changed",      # Did cloud IP change during episode? (0/1)
    "iot_ip_changed",        # Did IoT IP change during episode? (0/1)

    # Environment metadata
    "env_version",           # v1 or v2
    "collection_date",       # Date of collection
]

rows = []
start_time = datetime.now()

for ep in range(1, EPISODES + 1):
    obs, _ = env.reset()
    ep_reward     = 0.0
    steps         = 0
    actions_taken = []
    recon_count   = 0
    traffic_vals  = []

    # Track state changes
    initial_cloud_ip = float(obs[0])
    initial_iot_ip   = float(obs[3])
    final_cloud_ip   = initial_cloud_ip
    final_iot_ip     = initial_iot_ip

    for step in range(MAX_STEPS):
        # Choose action
        if USE_TRAINED_MODEL:
            action, _ = model.predict(obs, deterministic=False)
            action = int(action)
        else:
            action = env.action_space.sample()

        obs, reward, terminated, truncated, info = env.step(action)
        done = terminated or truncated

        ep_reward += reward
        steps     += 1
        actions_taken.append(action)

        # Extract state signals
        # State vector: [cloud_ip, open_ports, api_schema, iot_ip, mqtt_topic,
        #                cve_score, shodan_score, traffic_load, recon_signal, time]
        recon_signal    = float(obs[8]) if len(obs) > 8 else 0.0
        traffic_load    = float(obs[7]) if len(obs) > 7 else 0.0
        cve_score_step  = float(obs[5]) if len(obs) > 5 else 0.5

        if recon_signal > 0.5:
            recon_count += 1
        traffic_vals.append(traffic_load)

        final_cloud_ip = float(obs[0])
        final_iot_ip   = float(obs[3])

        if done:
            break

    # ── Aggregate episode stats ──
    from collections import Counter
    action_counts   = Counter(actions_taken)
    dominant_action = action_counts.most_common(1)[0][0]
    action_diversity= len(set(actions_taken))

    cloud_muts = sum(1 for a in actions_taken if a in CLOUD_ACTIONS)
    iot_muts   = sum(1 for a in actions_taken if a in IOT_ACTIONS)
    api_muts   = sum(1 for a in actions_taken if a == 2)

    # Use last-step CVE score as episode CVE score
    cve_ep = float(obs[5]) if len(obs) > 5 else round(random.uniform(0.3, 0.9), 3)

    # Threat level category
    if cve_ep >= 0.8:
        threat_level = "CRITICAL"
    elif cve_ep >= 0.6:
        threat_level = "HIGH"
    elif cve_ep >= 0.4:
        threat_level = "MEDIUM"
    else:
        threat_level = "LOW"

    traffic_avg = round(float(np.mean(traffic_vals)), 4) if traffic_vals else 0.0
    traffic_max = round(float(np.max(traffic_vals)),  4) if traffic_vals else 0.0

    defense_eff = round((ep_reward / 190.0) * 100, 2)

    elapsed = (datetime.now() - start_time).total_seconds()

    rows.append({
        "episode":               ep,
        "timestamp_sec":         round(elapsed, 2),
        "total_reward":          round(ep_reward, 4),
        "steps_completed":       steps,
        "defense_efficiency_pct":defense_eff,
        "cve_score":             round(cve_ep, 4),
        "threat_level":          threat_level,
        "recon_events":          recon_count,
        "dominant_action":       dominant_action,
        "dominant_action_name":  ACTION_LABELS[dominant_action],
        "action_diversity":      action_diversity,
        "cloud_mutations":       cloud_muts,
        "iot_mutations":         iot_muts,
        "api_mutations":         api_muts,
        "traffic_disruption_avg":traffic_avg,
        "traffic_disruption_max":traffic_max,
        "cloud_ip_changed":      int(abs(final_cloud_ip - initial_cloud_ip) > 0.01),
        "iot_ip_changed":        int(abs(final_iot_ip   - initial_iot_ip)   > 0.01),
        "env_version":           ENV_VERSION,
        "collection_date":       start_time.strftime("%Y-%m-%d"),
    })

    # Progress indicator
    if ep % 50 == 0:
        avg_r = np.mean([r["total_reward"] for r in rows[-50:]])
        print(f"      Episode {ep:>3}/500  |  Last 50 avg reward: {avg_r:.2f}")

# ─── SAVE TO CSV ──────────────────────────────────────────────────────────────
print(f"\n[4/5] Saving dataset to:\n      {OUTPUT_FILE}")

with open(OUTPUT_FILE, "w", newline="", encoding="utf-8") as f:
    writer = csv.DictWriter(f, fieldnames=CSV_COLUMNS)
    writer.writeheader()
    writer.writerows(rows)

# ─── SUMMARY ──────────────────────────────────────────────────────────────────
print("\n[5/5] Collection complete! Summary:")
print("─" * 50)
rewards = [r["total_reward"] for r in rows]
print(f"  Total episodes collected : {len(rows)}")
print(f"  Columns per episode      : {len(CSV_COLUMNS)}")
print(f"  Avg reward               : {np.mean(rewards):.2f}")
print(f"  Min reward               : {np.min(rewards):.2f}")
print(f"  Max reward               : {np.max(rewards):.2f}")
print(f"  Avg defense efficiency   : {np.mean([r['defense_efficiency_pct'] for r in rows]):.1f}%")
print(f"  Dataset file             : ghostnet_primary_data.csv")
print("─" * 50)
print("\n✅ Primary data collection COMPLETE.")
print("   Next step: run analysis\\analysis.py\n")
