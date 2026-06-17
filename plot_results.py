"""
GhostNet — Plot Training Results
==================================
Generates the training curve graph — Figure 1 in your research paper.
Run this after train.py completes.

Usage:
    python plot_results.py
"""

import numpy as np
import matplotlib.pyplot as plt
import matplotlib.patches as mpatches
import os


def plot_training_curve():
    path = "logs/evaluations.npz"
    if not os.path.exists(path):
        print("No evaluation data found. Run train.py first.")
        return

    data      = np.load(path)
    timesteps = data["timesteps"]
    results   = data["results"]
    mean_r    = results.mean(axis=1)
    std_r     = results.std(axis=1)
    best_r    = float(max(mean_r))
    best_t    = int(timesteps[np.argmax(mean_r)])

    fig, axes = plt.subplots(1, 2, figsize=(14, 5))
    fig.suptitle("GhostNet PPO Agent — Hospital Network Defense Results",
                 fontsize=14, fontweight='bold', y=1.01)

    # ── Left: Training curve ──────────────────────────────
    ax = axes[0]
    ax.plot(timesteps, mean_r, color='#185FA5', linewidth=2,
            marker='o', markersize=4, label='Mean reward')
    ax.fill_between(timesteps, mean_r - std_r, mean_r + std_r,
                    alpha=0.2, color='#185FA5', label='±1 std dev')
    ax.axhline(y=best_r, color='#1D9E75', linestyle='--',
               label=f'Best reward: {best_r:.1f}')
    ax.axvline(x=best_t, color='#BA7517', linestyle=':',
               label=f'Best at step: {best_t:,}')
    ax.set_xlabel("Training timesteps", fontsize=11)
    ax.set_ylabel("Mean episode reward", fontsize=11)
    ax.set_title("Training Reward Curve", fontsize=12)
    ax.legend(fontsize=9)
    ax.grid(True, alpha=0.3)

    # ── Right: Reward distribution ────────────────────────
    ax2 = axes[1]
    all_rewards = results.flatten()
    ax2.hist(all_rewards, bins=30, color='#185FA5', alpha=0.7,
             edgecolor='white')
    ax2.axvline(x=all_rewards.mean(), color='#1D9E75', linewidth=2,
                linestyle='--', label=f'Mean: {all_rewards.mean():.1f}')
    ax2.axvline(x=best_r, color='#E24B4A', linewidth=2,
                linestyle='--', label=f'Best: {best_r:.1f}')
    ax2.set_xlabel("Episode reward", fontsize=11)
    ax2.set_ylabel("Frequency", fontsize=11)
    ax2.set_title("Reward Distribution", fontsize=12)
    ax2.legend(fontsize=9)
    ax2.grid(True, alpha=0.3)

    plt.tight_layout()
    plt.savefig("ghostnet_results.png", dpi=150, bbox_inches='tight')
    plt.show()

    # Print summary
    print("\n" + "=" * 50)
    print("  GhostNet Training Summary")
    print("=" * 50)
    print(f"  Best reward       : {best_r:.1f} at step {best_t:,}")
    print(f"  Final reward      : {mean_r[-1]:.1f}")
    print(f"  Mean all evals    : {mean_r.mean():.1f}")
    print(f"  Max possible      : ~190")
    print(f"  Efficiency        : {(best_r/190)*100:.1f}% of theoretical max")
    print("=" * 50)
    print("  Figure saved: ghostnet_results.png")
    print("  Use this as Figure 1 in your research paper.")
    print("=" * 50)


if __name__ == "__main__":
    plot_training_curve()
