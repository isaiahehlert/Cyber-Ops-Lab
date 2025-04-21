.PHONY: quick-scan
quick-scan:
	python sentinel/quick_scan.py

.PHONY: ui log-stream
ui:
\tpython sentinel_ui.py

log-stream:
\tpython sentinel/log_stream.py

.PHONY: agent-local
agent-local:
\tpython sentinel/agent_local.py
