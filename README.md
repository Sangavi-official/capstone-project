# GhostNet — AI-Powered Moving Target Defense
## Hospital IoT + Cloud Security System

**Project:** GhostNet  
**Domain:** Hospital — ICU infusion pump to cloud pharmacy pipeline  
**Method:** Reinforcement Learning (PPO) + Moving Target Defense  
**Problem:** Static hospital networks give attackers time to map and exploit both IoT devices and cloud systems before striking

---

## Run order — do these in sequence

```
Step 1 — Test CVE live feed
python threat_feeds.py

Step 2 — Train the RL agent (with live CVE data)
python train.py

Step 3 — Plot training results (Figure 1 for paper)
python plot_results.py

Step 4 — Run live demo (for presentation)
python demo.py
```

---

## What each file does

| File | Phase | Purpose |
|------|-------|---------|
| `ghostnet_env.py`    | 1 | Hospital network simulator — base environment |
| `ghostnet_env_v2.py` | 2 | Upgraded environment with live CVE integration |
| `threat_feeds.py`    | 2 | NIST CVE API + Shodan live threat intelligence |
| `train.py`           | 1+2 | PPO agent training script |
| `plot_results.py`    | 1+2 | Training curve graph — Figure 1 for paper |
| `demo.py`            | 1+2 | Live 20-step demo for presentations |

---

## State space (10 dimensions)

| Index | Meaning | Real source (Phase 3+) |
|-------|---------|----------------------|
| 0 | Cloud IP exposure | AWS VPC visibility |
| 1 | Open ports | AWS Security Group rules |
| 2 | API exposure | API Gateway access logs |
| 3 | IoT gateway IP | OpenWRT router status |
| 4 | MQTT topic exposure | Mosquitto broker logs |
| 5 | CVE threat score | NIST NVD API (live) |
| 6 | Shodan score | Shodan API (live) |
| 7 | Traffic load | AWS CloudWatch |
| 8 | Recon attempts | Firewall logs |
| 9 | Time since mutation | Internal clock |

---

## Action space (6 mutations)

| Action | Mutation | Defends against |
|--------|----------|----------------|
| 0 | Rotate cloud IP | IP scanning, DoS |
| 1 | Close open port | Port scanning, exploitation |
| 2 | Rotate API path | API enumeration, injection |
| 3 | Rotate IoT gateway IP | IoT device scanning |
| 4 | Rotate MQTT topic | MQTT eavesdropping, spoofing |
| 5 | Update firewall | Pattern-based attacks |

---

## TADR Reward Formula

```
Reward = attacker_disruption - traffic_penalty - mutation_cost + cve_bonus

Where:
  attacker_disruption = 1.0 - new_exposure_value    (max ~0.95)
  traffic_penalty     = traffic_load × 0.2           (protects patients)
  mutation_cost       = 0.05                         (cost of any change)
  cve_bonus           = 0.1 if high CVE + right action
```

---

## Results

- Best reward: 159.8 / 190 maximum = **84% optimal defense efficiency**
- Agent learned to mutate aggressively when traffic is low
- Agent holds back when hospital traffic load is high (protects patients)
- TADR reward function working as designed

---

## Phases roadmap

- [x] Phase 0 — Environment setup, CartPole RL test
- [x] Phase 1 — GhostNet environment + PPO training
- [x] Phase 2 — Live CVE threat feed integration (LTSA)
- [ ] Phase 3 — Real AWS VPC mutations (cloud_mutator.py)
- [ ] Phase 4 — Raspberry Pi IoT testbed
- [ ] Phase 5 — CALDERA red agent + Nash equilibrium evaluation
- [ ] Phase 6 — Research paper write-up

---

## References

1. Gayathri et al. — "Detection and Mitigation of IoT-Based Attacks Using SNMP and MTD" — VIT Chennai, Sensors 2023
2. Sharma — "Evaluating MTD Methods Using Time to Compromise in IoT Networks" — U of Toronto, Electronics 2025
3. AIIMS Delhi Ransomware Analysis — ResearchGate 2024
4. Palo Alto Networks — "Medical IoT Security Solution Brief" — 2024
5. Armis — "Cybersecurity Blueprint 2025"
