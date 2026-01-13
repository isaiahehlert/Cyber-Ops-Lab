# MiniSOC (Home SOC / Mini-SIEM)

Pi-friendly, local-first mini-SIEM: ingest -> normalize -> enrich -> detect -> score -> alert -> timeline -> report.

## Architecture
┌───────────────┐    HTTP POST(JSON)     ┌─────────────────────┐
│ AGENT         │ ─────────────────────► │ SERVER              │
│ tail logs     │                        │ ingest + validate    │
│ parse/normalize                        │ store (SQLite/JSONL) │
│ forward        │                        │ enrich + detect      │
└───────────────┘                        │ alert + timeline     │
│ daily report (MD)    │
└─────────────────────┘
