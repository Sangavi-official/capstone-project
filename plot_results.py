import numpy as np
import matplotlib.pyplot as plt

# Load evaluation results
data = np.load("logs/evaluations.npz")
timesteps = data["timesteps"]
rewards   = data["results"].mean(axis=1)

plt.figure(figsize=(10, 5))
plt.plot(timesteps, rewards, color='#185FA5', linewidth=2, marker='o', markersize=4)
plt.fill_between(timesteps, rewards - data["results"].std(axis=1),
                              rewards + data["results"].std(axis=1),
                              alpha=0.2, color='#185FA5')
plt.xlabel("Training timesteps", fontsize=12)
plt.ylabel("Mean reward", fontsize=12)
plt.title("GhostNet PPO Agent — Hospital Network Defense Training", fontsize=13)
plt.axhline(y=max(rewards), color='#1D9E75', linestyle='--',
            label=f'Best reward: {max(rewards):.1f}')
plt.legend()
plt.grid(True, alpha=0.3)
plt.tight_layout()
plt.savefig("training_curve.png", dpi=150)
plt.show()
print(f"Best reward achieved: {max(rewards):.1f}")
print(f"Final reward: {rewards[-1]:.1f}")
print("Graph saved as training_curve.png")