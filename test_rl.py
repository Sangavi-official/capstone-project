from stable_baselines3 import PPO
import gymnasium as gym

env = gym.make("CartPole-v1")
model = PPO("MlpPolicy", env, verbose=1)
model.learn(total_timesteps=20000)
print("===========================")
print("RL stack working perfectly.")
print("===========================")