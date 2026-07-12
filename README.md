# GhostNet — Autonomous RL-Based Moving Target Defense for Hospital IoT & Cloud

[![Python](https://img.shields.io/badge/Python-3.12.7-blue?logo=python)](https://www.python.org/)
[![Algorithm](https://img.shields.io/badge/PPO-stable--baselines3-green)](https://stable-baselines3.readthedocs.io/)
[![Cloud](https://img.shields.io/badge/AWS-boto3-orange?logo=amazon-aws)](https://aws.amazon.com/)
[![IoT](https://img.shields.io/badge/Mosquitto-MQTT%202.1.2-purple)](https://mosquitto.org/)
[![Eval](https://img.shields.io/badge/Red%20Team-MITRE%20CALDERA-red)](https://caldera.mitre.org/)

> A PPO-based reinforcement learning agent that autonomously mutates hospital cloud and IoT attack surfaces in real time — making the network a moving target that attackers cannot map fast enough to exploit.

---

## Why This Exists

| Attack | Year | Impact |
|--------|------|--------|
| **AIIMS Delhi** ransomware | 2022 | 40+ servers encrypted; 15M+ patient records exposed; critical care disrupted for weeks |
| **PIH Health** ransomware (California) | 2025 | 3 hospitals taken offline simultaneously; surgeries diverted; pharmacy systems down |

Both attacks exploited **static, predictable infrastructure**. GhostNet eliminates static targets.

---

## System Architecture

![GhostNet Architecture](docs/architecture.png)

> The agent sits between threat intelligence and infrastructure — observing live threat signals, deciding which mutation to apply, and executing it across cloud and IoT simultaneously.

---

## How Mutation Works

```
Live Threat Feeds (NIST CVE, Shodan, AbuseIPDB, MITRE ATT&CK)
        │
        ▼
  12-Dimensional State Vector
  [ cve_score, shodan_exposure, abuse_score, attck_score,
    port_entropy, ip_rotation_flag, session_age, ...  ]
        │
        ▼
  PPO Agent → selects mutation action
        │
        ├──▶  AWS Security Group: rotate ingress ports, drop suspicious IPs
        ├──▶  MQTT Topic: shift namespace, invalidate stale subscriptions
        ├──▶  API Schema: mutate endpoint structure
        └──▶  Credentials: rotate access keys, update IAM policies

  Attacker's reconnaissance map → STALE before exploitation completes
```

Every mutation is driven by the live threat state — not a fixed schedule. High CVE scores trigger port rotation; high AbuseIPDB scores trigger IP blocklist updates; MITRE ATT&CK hits (healthcare-filtered) trigger full surface reshuffling.

---

## Results

```
Training run — stable-baselines3 PPO
─────────────────────────────────────────────────────────
  Timesteps         :  100,000
  State dimensions  :  12
  Live threat feeds :  4 (concurrent, real-time)

  Baseline reward   :  159.8   (no live threat context)
  Final reward      :  171.9   (with live feeds integrated)
  Improvement       :  +7.6%

  AWS mutations     :  Live (Security Group sg-011b5416a5dfa61b8, ap-south-1)
  IoT telemetry     :  Mosquitto MQTT — simulated ICU infusion pump
  Defense mode      :  Fully autonomous, zero human intervention
─────────────────────────────────────────────────────────
| ep_len_mean       |        498         |
| ep_rew_mean       |       171.9        |
| fps               |        312         |
| policy_loss       |     -0.00842       |
| value_loss        |       0.438        |
─────────────────────────────────────────────────────────
```

---

## Tech Stack

| Layer | Stack |
|-------|-------|
| RL Agent | PPO · `stable-baselines3` · `gymnasium` |
| Threat Feeds | NIST NVD CVE API · Shodan · AbuseIPDB · MITRE ATT&CK |
| Cloud | AWS boto3 · Security Groups · IAM · EC2 |
| IoT | Mosquitto MQTT v2.1.2 · `device.py` · `paramiko` |
| Red Team Eval | MITRE CALDERA (Docker) |
| Dashboard | Three.js · Socket.IO · `bridge_server.py` |
| Language | Python 3.12.7 |

---

## Setup

### 1 — Mosquitto (PowerShell, run as Admin)
```powershell
Set-Content -Path "C:\Program Files\mosquitto\ghostnet.conf" -Value "listener 1883`nallow_anonymous true`nlistener 9001`nprotocol websockets`nallow_anonymous true"
& "C:\Program Files\mosquitto\mosquitto.exe" -c "C:\Program Files\mosquitto\ghostnet.conf" -v
```

### 2 — IoT Simulation
```bash
python device.py          # publishes infusion pump telemetry over MQTT
```

### 3 — Agent
```bash
python train.py           # train from scratch
python run_phase3.py      # run with live AWS mutations
python demo.py            # demo with saved model
```

### 4 — Dashboard
```bash
python bridge_server.py   # start Socket.IO bridge
# open dashboard/index.html in browser
```

### 5 — Red Team (CALDERA)
```bash
docker run -p 8888:8888 mitre/caldera
# http://localhost:8888 — launch adversarial campaigns against live GhostNet
```

---

## Project Structure

```
ghostnet/
├── ghostnet_env_v3.py    # Custom Gym env — 12-dim state, TADR reward
├── threat_feeds.py       # Live threat intelligence aggregator
├── cloud_mutator.py      # AWS Security Group mutations (boto3)
├── iot_mutator.py        # IoT surface mutation via paramiko SSH
├── train.py              # PPO training
├── run_phase3.py         # Live cloud mutation runner
├── demo.py               # Saved-model demo
├── device.py             # Simulated infusion pump (MQTT)
├── bridge_server.py      # Socket.IO dashboard bridge
├── dashboard/index.html  # Live 3D visualization (Three.js)
├── ghostnet_pitch.html   # Standalone replay dashboard
├── docs/architecture.png # System architecture diagram
└── models/
    ├── ghostnet_final.zip
    └── best_model/best_model.zip
```

---

## Reference

Yoon, S. et al. *"DESOLATER: A Moving Target Defense Technique Based on Connection Migration."* IEEE Access, 2021.

---

**Team Mirai** · Sangavi S. · Suha N. · Final Year Capstone
