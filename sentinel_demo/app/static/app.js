let lastAlertTimestamp = null;

function setBadge(overall) {
    const badge = document.getElementById("status-badge");
    badge.className = "badge";

    if (overall === "high_risk") {
        badge.classList.add("high");
        badge.innerText = "HIGH RISK";
    } else if (overall === "suspicious") {
        badge.classList.add("medium");
        badge.innerText = "SUSPICIOUS";
    } else if (overall === "low_signal") {
        badge.classList.add("low");
        badge.innerText = "LOW SIGNAL";
    } else {
        badge.classList.add("clean");
        badge.innerText = "MONITORING";
    }
}

function renderDetections(history) {
    const body = document.getElementById("detections-body");

    if (!history || history.length === 0) {
        body.innerHTML = `
            <tr>
              <td colspan="6" class="empty">Awaiting telemetry. No detections.</td>
            </tr>
        `;
        return;
    }

    const ordered = [...history].reverse();

    body.innerHTML = ordered.map(d => `
        <tr class="fade-in">
          <td>${d.detected_at || "-"}</td>
          <td>${d.type || "-"}</td>
          <td class="sev-${d.severity || "info"}">${d.severity || "-"}</td>
          <td>${d.source_ip || d.metrics?.top_ip_at_peak || "-"}</td>
          <td>${d.score ?? "-"}</td>
          <td>${(d.evidence || []).join("; ")}</td>
        </tr>
    `).join("");
}

function renderAlertBanner(alert) {
    const banner = document.getElementById("alert-banner");
    const text = document.getElementById("alert-banner-text");

    if (!alert) {
        banner.className = "alert-banner hidden";
        text.innerText = "";
        return;
    }

    text.innerText = alert.message || "ALERT";
    banner.className = `alert-banner show ${alert.severity || "medium"}`;

    if (alert.timestamp && alert.timestamp !== lastAlertTimestamp) {
        banner.classList.remove("flash");
        void banner.offsetWidth;
        banner.classList.add("flash");
        lastAlertTimestamp = alert.timestamp;
    }
}

async function fetchState() {
    const res = await fetch("/api/state");
    const data = await res.json();

    const overall = data.overall || "clean";

    document.getElementById("overall-status").innerText =
        overall === "clean" ? "monitoring" : overall;

    document.getElementById("source").innerText = data.source || "monitoring";
    document.getElementById("last-updated").innerText = data.last_updated || "-";
    document.getElementById("summary").innerText = JSON.stringify(data.summary || {});

    setBadge(overall);
    renderDetections(data.detection_history || []);
    renderAlertBanner(data.alert_banner || null);
}

async function resetState() {
    await fetch("/api/reset", { method: "POST" });
    lastAlertTimestamp = null;
    fetchState();
}

async function clearAlert() {
    await fetch("/api/clear-alert", { method: "POST" });
    fetchState();
}

setInterval(fetchState, 1500);
fetchState();
