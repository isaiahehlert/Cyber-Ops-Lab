# 🛡️ Cyber-Ops-Lab

A repository of customized tools, logs, and documentation used in cybersecurity research, testing, and learning.

## 📁 Directories

- `scripts/`: Python tools for recon, scanning, and parsing
- `logs/`: Packet captures, system events, traffic analysis
- `tools/`: Helpers & wrappers for utilities like Nmap
- `references/`: Cheat sheets and study notes (Linux, regex, vulnerabilities)

## 🚧 Status
Project under active development. Tools and references are being added progressively.
---

## 🧰 Current Toolset

### `minisoc/` — Minimal SOC Simulator  
A self-contained detection lab framework designed for simulating alert workflows, replaying attack scenarios, and testing detection logic.

**Features:**
- 🧪 Agent/server model for replaying telemetry
- ⚙️ Configurable replay scenarios (JSONL)
- 🔎 Example detections (impossible travel, password spray, SSH brute-force)
- 🧼 Clean Python CLI interface via `cli.py`
- 🧪 Test coverage in `tests/`
- 🐍 Built with `pyproject.toml` (PEP 518-style)

**Paths:**
- `tools/minisoc/configs/` — Example configs
- `tools/minisoc/data/replay_scenarios/` — JSONL attack flows
- `tools/minisoc/src/minisoc/` — Agent, server, CLI logic
- `tools/minisoc/tests/` — Unit tests for detection + storage

> See the [`tools/minisoc/README.md`](./tools/minisoc/README.md) for more information.
