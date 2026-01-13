from flask import Flask, request, render_template_string
import os
import re

app = Flask(__name__)

def read_time(path):
    if os.path.exists(path):
        with open(path) as f:
            return f.read().strip()
    return "Never"

@app.route("/", methods=["GET", "POST"])
def dashboard():
    message = ""
    if request.method == "POST":
        action = request.form.get("action")
        if action == "scan":
            os.system("python3 sentinel/sentinel_scanner.py")
            os.system("date > sentinel_logs/scanner.txt")
            message = "✅ Device scan complete."
        elif action == "log":
            os.system("python3 sentinel/sentinel_logger.py")
            os.system("date > sentinel_logs/logger.txt")
            message = "📄 Traffic log generated."
        elif action == "detect":
            os.system("python3 sentinel/sentinel_detector.py")
            os.system("date > sentinel_logs/detector.txt")
            message = "🧠 Threat detection complete."

    last_scan = read_time("sentinel_logs/scanner.txt")
    last_log = read_time("sentinel_logs/logger.txt")
    last_detect = read_time("sentinel_logs/detector.txt")

    return render_template_string("""
        <h1>🛡️ Sentinel Dashboard</h1>
        <h3>📊 Last Run Status</h3>
        <ul>
            <li>📡 Device Scan: {{ last_scan }}</li>
            <li>📄 Traffic Log: {{ last_log }}</li>
            <li>🧠 Threat Detector: {{ last_detect }}</li>
        </ul>
        <form method="post">
            <button name="action" value="scan">📡 Scan Devices</button>
            <button name="action" value="log">📄 Generate Logs</button>
            <button name="action" value="detect">🧠 Run Detector</button>
        </form>
        <p><a href="/logs">📁 View Logs</a></p>
        <p>{{ message }}</p>
    """, message=message, last_scan=last_scan, last_log=last_log, last_detect=last_detect)

@app.route("/logs")
def view_logs():
    filter_type = request.args.get("filter", "").lower()
    all_logs = []
    logs_by_file = []

    def read_lines(path):
        with open(path) as f:
            return [line.strip() for line in f if line.strip()]

    if os.path.exists("sentinel_reports"):
        files = sorted(os.listdir("sentinel_reports"), key=lambda x: os.path.getmtime(os.path.join("sentinel_reports", x)), reverse=True)
        for fname in files:
            if fname.startswith("report_flagged_traffic_"):
                lines = read_lines(os.path.join("sentinel_reports", fname))
                all_logs.extend(lines)
                if filter_type:
                    lines = [l for l in lines if filter_type in l.lower()]
                logs_by_file.append((fname, lines))

    def extract_types(logs):
        found = set()
        for line in logs:
            match = re.search(r"User-Agent: ([^\\s]+)", line)
            if match:
                found.add(match.group(1).lower())
            for keyword in ["sqlmap", "curl", "python-requests", "wget", "nmap", "nuclei", "nikto", "fuzz"]:
                if keyword in line.lower():
                    found.add(keyword)
        return sorted(found)

    threats = extract_types(all_logs)

    return render_template_string("""
        <h1>📂 Flagged Logs</h1>

        {% set emojis = {
            'sqlmap': '💉 SQLMap',
            'curl': '🌊 Curl',
            'python-requests': '🐍 Python',
            'wget': '📥 Wget',
            'nmap': '🛰️ Nmap',
            'nuclei': '🧬 Nuclei',
            'nikto': '🏴‍☠️ Nikto',
            'fuzz': '🧯 Fuzz'
        } %}

        <form method="get" action="/logs">
            {% for t in threats %}
                <button name="filter" value="{{ t }}">{{ emojis.get(t, '🧪 ' ~ t) }}</button>
            {% endfor %}
            <button name="filter" value="">📋 Show All</button>
        </form>

        {% for fname, lines in logs_by_file %}
            {% if lines %}
                <h3>🧾 {{ fname }}</h3>
                <pre>{{ lines | join('\\n') }}</pre>
            {% endif %}
        {% endfor %}

        <p><a href='/'>⬅️ Back to Dashboard</a></p>
    """, logs_by_file=logs_by_file, threats=threats)

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
