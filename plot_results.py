"""
GhostNet — Training Results Visualization
=============================================
Generates the training reward curve and reward distribution
figure used as evidence of agent learning. Run after train.py.
"""

import numpy as np
import matplotlib.pyplot as plt
import os

print("=" * 50)
print("  GhostNet — Plotting Training Results")
print("=" * 50)

if not os.path.exists("logs/evaluations.npz"):
    print("  No evaluation data found. Run train.py first.")
    raise SystemExit

data      = np.load("logs/evaluations.npz")
timesteps = data["timesteps"]
results   = data["results"]
mean_r    = results.mean(axis=1)
std_r     = results.std(axis=1)
best_r    = float(max(mean_r))
best_t    = int(timesteps[np.argmax(mean_r)])

fig, axes = plt.subplots(1, 2, figsize=(14, 5))
fig.suptitle("GhostNet PPO Agent — Hospital Network Defense Training",
             fontsize=14, fontweight="bold")

ax = axes[0]
ax.plot(timesteps, mean_r, color="#185FA5", linewidth=2,
        marker="o", markersize=4, label="Mean reward")
ax.fill_between(timesteps, mean_r - std_r, mean_r + std_r,
                alpha=0.2, color="#185FA5", label="±1 std dev")
ax.axhline(y=best_r, color="#1D9E75", linestyle="--",
           label=f"Best reward: {best_r:.1f}")
ax.axvline(x=best_t, color="#BA7517", linestyle=":",
           label=f"Best at step {best_t:,}")
ax.set_xlabel("Training timesteps", fontsize=11)
ax.set_ylabel("Mean episode reward", fontsize=11)
ax.set_title("Training Reward Curve", fontsize=12)
ax.legend(fontsize=9)
ax.grid(True, alpha=0.3)

ax2 = axes[1]
all_r = results.flatten()
ax2.hist(all_r, bins=30, color="#185FA5", alpha=0.7, edgecolor="white")
ax2.axvline(x=all_r.mean(), color="#1D9E75", linewidth=2,
            linestyle="--", label=f"Mean: {all_r.mean():.1f}")
ax2.axvline(x=best_r, color="#E24B4A", linewidth=2,
            linestyle="--", label=f"Best: {best_r:.1f}")
ax2.set_xlabel("Episode reward", fontsize=11)
ax2.set_ylabel("Frequency", fontsize=11)
ax2.set_title("Reward Distribution", fontsize=12)
ax2.legend(fontsize=9)
ax2.grid(True, alpha=0.3)

plt.tight_layout()
plt.savefig("ghostnet_results.png", dpi=150, bbox_inches="tight")
plt.show()

print(f"\n  Best reward    : {best_r:.1f} at step {best_t:,}")
print(f"  Final reward   : {mean_r[-1]:.1f}")
print(f"  Efficiency      : {(best_r/190)*100:.1f}% of theoretical maximum")
print(f"  Figure saved    : ghostnet_results.png")
print("=" * 50)
