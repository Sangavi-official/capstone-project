"""
phase5_visualize.py — GhostNet Phase 5: Results Visualization
===============================================================
Reads phase5_results.json and produces 4 IEEE-ready figures:

  Figure 1 — Reward trajectory (all 3 scenarios, mean ± std band)
  Figure 2 — Threat score over time with mutation events overlaid
  Figure 3 — Attack Success Rate bar chart (RL-MTD vs Static vs Baseline)
  Figure 4 — Summary metrics table (MTTD, MTTR, reward, mutations)

Output files (saved to ./phase5_figures/):
  fig1_reward_trajectory.png
  fig2_threat_with_mutations.png
  fig3_attack_success_rate.png
  fig4_summary_table.png

Usage:
    python phase5_visualize.py

Requires:
    pip install matplotlib numpy
"""

import json
import numpy as np
import matplotlib.pyplot as plt
import matplotlib.patches as mpatches
from pathlib import Path

# ── Config ────────────────────────────────────────────────────────────────────
RESULTS_FILE = "phase5_results.json"
OUTPUT_DIR   = Path("phase5_figures")

# IEEE-style plot settings
plt.rcParams.update({
    "font.family":     "serif",
    "font.size":       11,
    "axes.titlesize":  12,
    "axes.labelsize":  11,
    "legend.fontsize": 9,
    "figure.dpi":      300,
    "lines.linewidth": 1.8,
})

COLORS = {
    "baseline":      "#2196F3",  # blue
    "under_attack":  "#F44336",  # red
    "static_defense":"#FF9800",  # orange
}
LABELS = {
    "baseline":      "RL-MTD (No Attack)",
    "under_attack":  "RL-MTD Under Attack",
    "static_defense":"Static Defense Under Attack",
}


# ── Helpers ───────────────────────────────────────────────────────────────────

def load_results(path: str) -> dict:
    with open(path) as f:
        return json.load(f)


def cumulative_rewards(episodes: list, max_steps: int) -> np.ndarray:
    """
    Build a [num_episodes × max_steps] matrix of cumulative per-step rewards.
    Pads shorter episodes with their final cumulative value.
    """
    matrix = []
    for ep in episodes:
        cum = 0.0
        row = []
        for s in ep["step_log"]:
            cum += s["reward"]
            row.append(cum)
        # Pad to max_steps
        row += [row[-1]] * (max_steps - len(row))
        matrix.append(row[:max_steps])
    return np.array(matrix)


def threat_series(episode: dict, dim: int = 11) -> np.ndarray:
    """Extract one state dimension over time for a single episode."""
    return np.array([s["obs"][dim] for s in episode["step_log"]])


def mutation_steps(episode: dict) -> list:
    """Steps where the agent took a non-zero action (= mutation)."""
    return [s["step"] for s in episode["step_log"] if s["action"] != 0]


# ── Figure 1: Reward Trajectory ───────────────────────────────────────────────

def fig1_reward_trajectory(results: dict, max_steps: int = 200):
    fig, ax = plt.subplots(figsize=(7, 4))
    x = np.arange(max_steps)

    for scenario, color in COLORS.items():
        if scenario not in results:
            continue
        episodes = results[scenario]["episodes"]
        mat      = cumulative_rewards(episodes, max_steps)
        mean     = mat.mean(axis=0)
        std      = mat.std(axis=0)

        ax.plot(x, mean, color=color, label=LABELS[scenario])
        ax.fill_between(x, mean - std, mean + std, alpha=0.15, color=color)

    ax.set_xlabel("Environment Step")
    ax.set_ylabel("Cumulative Reward")
    ax.set_title("GhostNet RL-MTD: Reward Trajectory Under Adversarial Attack")
    ax.legend(loc="upper left")
    ax.grid(True, linestyle="--", alpha=0.4)

    plt.tight_layout()
    path = OUTPUT_DIR / "fig1_reward_trajectory.png"
    plt.savefig(path)
    plt.close()
    print(f"Saved: {path}")


# ── Figure 2: Threat Score + Mutations ────────────────────────────────────────

def fig2_threat_with_mutations(results: dict):
    """
    Shows ransomware_risk (dim 11) over time for the median under_attack episode,
    with vertical lines marking every agent mutation event.
    """
    if "under_attack" not in results:
        return

    episodes = results["under_attack"]["episodes"]

    # Pick median episode by total reward
    rewards  = [e["episode_reward"] for e in episodes]
    med_idx  = int(np.argsort(rewards)[len(rewards) // 2])
    ep       = episodes[med_idx]

    fig, (ax1, ax2) = plt.subplots(2, 1, figsize=(8, 5), sharex=True)

    # Panel 1: ransomware risk (dim 11)
    risk = threat_series(ep, dim=11)
    steps = np.arange(len(risk))
    ax1.plot(steps, risk, color="#F44336", label="Ransomware Risk (dim 11)")
    ax1.set_ylabel("Threat Score")
    ax1.set_ylim(0, 1.05)
    ax1.legend(loc="upper left")
    ax1.grid(True, linestyle="--", alpha=0.4)

    # Panel 2: reward per step
    rewards_step = [s["reward"] for s in ep["step_log"]]
    ax2.bar(steps, rewards_step, color="#2196F3", alpha=0.7, label="Step Reward")
    ax2.set_ylabel("Reward")
    ax2.set_xlabel("Step")
    ax2.legend(loc="upper left")

    # Overlay mutation events on both panels
    muts = mutation_steps(ep)
    for m in muts:
        ax1.axvline(x=m, color="green", linewidth=0.7, alpha=0.6, linestyle=":")
        ax2.axvline(x=m, color="green", linewidth=0.7, alpha=0.6, linestyle=":")

    green_patch = mpatches.Patch(color="green", alpha=0.6, label="Mutation event")
    ax1.legend(handles=[
        mpatches.Patch(color="#F44336", label="Ransomware Risk (dim 11)"),
        green_patch,
    ], loc="upper left")

    fig.suptitle("Threat Score and Agent Mutations (Median Episode Under Attack)")
    plt.tight_layout()
    path = OUTPUT_DIR / "fig2_threat_with_mutations.png"
    plt.savefig(path)
    plt.close()
    print(f"Saved: {path}")


# ── Figure 3: Attack Success Rate Bar Chart ───────────────────────────────────

def fig3_attack_success_rate(results: dict):
    scenarios = ["baseline", "under_attack", "static_defense"]
    labels    = [LABELS[s] for s in scenarios if s in results]
    rates     = [results[s]["summary"]["attack_success_rate"] * 100
                 for s in scenarios if s in results]
    colors    = [COLORS[s] for s in scenarios if s in results]

    fig, ax = plt.subplots(figsize=(6, 4))
    bars = ax.bar(labels, rates, color=colors, width=0.5, edgecolor="white")

    for bar, rate in zip(bars, rates):
        ax.text(
            bar.get_x() + bar.get_width() / 2,
            bar.get_height() + 0.5,
            f"{rate:.1f}%",
            ha="center", va="bottom", fontweight="bold"
        )

    ax.set_ylabel("Attack Success Rate (%)")
    ax.set_title("Adversarial Attack Success Rate by Defense Strategy")
    ax.set_ylim(0, 110)
    ax.tick_params(axis="x", labelrotation=12)
    ax.grid(axis="y", linestyle="--", alpha=0.4)

    plt.tight_layout()
    path = OUTPUT_DIR / "fig3_attack_success_rate.png"
    plt.savefig(path)
    plt.close()
    print(f"Saved: {path}")


# ── Figure 4: Summary Metrics Table ──────────────────────────────────────────

def fig4_summary_table(results: dict):
    col_labels = ["Metric", "RL-MTD\n(No Attack)", "RL-MTD\n(Under Attack)", "Static\n(Under Attack)"]
    scenarios  = ["baseline", "under_attack", "static_defense"]

    def fmt(value, suffix=""):
        if value is None:
            return "—"
        if isinstance(value, float):
            return f"{value:.2f}{suffix}"
        return str(value)

    rows = []

    # Mean reward
    row = ["Mean Episode Reward"]
    for s in scenarios:
        row.append(fmt(results.get(s, {}).get("summary", {}).get("mean_reward")))
    rows.append(row)

    # Std reward
    row = ["Reward Std Dev"]
    for s in scenarios:
        row.append(fmt(results.get(s, {}).get("summary", {}).get("std_reward")))
    rows.append(row)

    # Mean mutations
    row = ["Mutations / Episode"]
    for s in scenarios:
        row.append(fmt(results.get(s, {}).get("summary", {}).get("mean_mutations"), ""))
    rows.append(row)

    # MTTD
    row = ["MTTD (steps)"]
    for s in scenarios:
        row.append(fmt(results.get(s, {}).get("summary", {}).get("mttd_mean_steps"), ""))
    rows.append(row)

    # Attack success rate
    row = ["Attack Success Rate"]
    for s in scenarios:
        rate = results.get(s, {}).get("summary", {}).get("attack_success_rate")
        row.append(f"{rate*100:.1f}%" if rate is not None else "—")
    rows.append(row)

    fig, ax = plt.subplots(figsize=(9, 3))
    ax.axis("off")
    table = ax.table(
        cellText=rows,
        colLabels=col_labels,
        loc="center",
        cellLoc="center",
    )
    table.auto_set_font_size(False)
    table.set_fontsize(9)
    table.scale(1, 1.6)

    # Header row styling
    for col in range(len(col_labels)):
        table[0, col].set_facecolor("#37474F")
        table[0, col].set_text_props(color="white", fontweight="bold")

    # Alternating row colours
    for row in range(1, len(rows) + 1):
        for col in range(len(col_labels)):
            if row % 2 == 0:
                table[row, col].set_facecolor("#ECEFF1")

    ax.set_title("GhostNet Phase 5 — Evaluation Metrics Summary",
                 fontsize=12, fontweight="bold", pad=16)
    plt.tight_layout()
    path = OUTPUT_DIR / "fig4_summary_table.png"
    plt.savefig(path, bbox_inches="tight")
    plt.close()
    print(f"Saved: {path}")


# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    OUTPUT_DIR.mkdir(exist_ok=True)

    print(f"Loading results from: {RESULTS_FILE}")
    results = load_results(RESULTS_FILE)

    # Infer max_steps from data
    max_steps = max(
        len(ep["step_log"])
        for scenario in results.values()
        for ep in scenario["episodes"]
    )

    print(f"Generating figures (max_steps={max_steps})...")
    fig1_reward_trajectory(results, max_steps=max_steps)
    fig2_threat_with_mutations(results)
    fig3_attack_success_rate(results)
    fig4_summary_table(results)

    print(f"\nAll figures saved to: {OUTPUT_DIR.resolve()}")
    print("Use these directly in your IEEE paper (300 DPI PNG).")


if __name__ == "__main__":
    main()
