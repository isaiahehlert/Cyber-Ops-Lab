# 🧰 minisoc — Minimal SOC Simulator

`minisoc` is under **active development and testing** as a local, controlled lab environment for detection engineering and attack simulation. The system is built to remain fully self-contained and avoids external dependencies or cloud services.

---

## 🔐 Focus

- **Current Objective:** Build and validate tooling that detects SSH daemon (sshd) takeover attempts.  
- **Design Goal:** All detection and replay logic must function in fully local environments with zero external connectivity.

---

## 🛠️ Planned Features (Post-Validation)

Once sshd compromise detection tooling is validated:

- 🛡️ **Networking watchdog**: Custom tooling to monitor and validate unexpected network activity  
- 🧪 **Responsive sandboxing**: Detection of malicious behavior will trigger system isolation routines  
- 📡 **Telemetry replay**: Continue expanding `replay_scenarios/` with diverse attack sequences  

---

## 📂 Structure Overview

- `configs/` — Example YAML configuration files  
- `data/replay_scenarios/` — Simulated attacks in JSONL format  
- `src/minisoc/` — Core logic for agent/server operations  
- `tests/` — Detection logic and storage backend tests  

---

## 🚧 Status

Prototype in progress. Actively expanding detection logic and stabilizing agent/server behavior.

> Contributions currently closed while foundational logic is being finalized.
