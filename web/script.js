let pollTimer = null;
let trafficHistory = Array(42).fill(0);
let lastAnalysis = null;
let lastAlerts = [];
let lastPackets = [];

async function fetchJSON(url, options = {}) {
    try {
        const res = await fetch(url, { headers: { "Content-Type": "application/json" }, ...options });
        return await res.json();
    } catch (e) {
        console.error("Fetch error:", e);
        return null;
    }
}

function escapeHTML(value) {
    return String(value ?? "").replace(/[&<>"']/g, c => ({
        "&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#039;"
    }[c]));
}

function setStatus(text, isError = false) {
    const el = document.getElementById("statusText");
    el.innerHTML = `<i></i> ${escapeHTML(text)}`;
    el.className = "status-pill" + (isError ? " error" : "");
}

function setCaptureUI(running, iface = "", durationSec = 0) {
    const dot = document.getElementById("liveDot");
    const title = document.getElementById("captureTitle");
    const sub = document.getElementById("captureSub");
    dot.classList.toggle("on", running);
    title.textContent = running ? "Live monitoring active" : "Ready to monitor";
    sub.textContent = running
        ? `Capturing on ${iface}` + (durationSec > 0 ? ` · ${formatDuration(durationSec)}` : "")
        : "Select a network interface to begin";
}

function formatBytes(bytes) {
    const b = Number(bytes) || 0;
    if (b < 0) return "-" + formatBytes(-b);
    if (b < 1024) return `${b} B`;
    const units = ["KB", "MB", "GB", "TB"];
    let i = -1;
    let v = b;
    do { v /= 1024; i++; } while (v >= 1024 && i < units.length - 1);
    return `${v.toFixed(v >= 100 ? 0 : v >= 10 ? 1 : 2)} ${units[i]}`;
}

function formatDuration(sec) {
    const s = Math.floor(Number(sec) || 0);
    const h = String(Math.floor(s / 3600)).padStart(2, "0");
    const m = String(Math.floor((s % 3600) / 60)).padStart(2, "0");
    const ss = String(s % 60).padStart(2, "0");
    return `${h}:${m}:${ss}`;
}

async function loadInterfaces() {
    const data = await fetchJSON("/api/interfaces");
    const select = document.getElementById("interfaceSelect");
    if (data?.interfaces?.length) {
        select.innerHTML = "";
        data.interfaces.forEach(iface => {
            const opt = document.createElement("option");
            if (typeof iface === "object" && iface !== null) {
                opt.value = iface.id;
                opt.textContent = iface.name + (iface.description ? " — " + iface.description : "");
            } else {
                opt.value = iface;
                opt.textContent = iface;
            }
            select.appendChild(opt);
        });
    } else {
        select.innerHTML = '<option value="">No interfaces found</option>';
    }
}

async function startCapture() {
    const iface = document.getElementById("interfaceSelect").value;
    if (!iface) { setStatus("Select an interface first", true); return; }

    const result = await fetchJSON("/api/start", {
        method: "POST",
        body: JSON.stringify({ interface: iface })
    });

    if (result?.status === "started") {
        setStatus("Monitoring " + iface);
        document.getElementById("startBtn").disabled = true;
        document.getElementById("stopBtn").disabled = false;
        setCaptureUI(true, iface);
        if (pollTimer) clearInterval(pollTimer);
        pollTimer = setInterval(refreshData, 1000);
        refreshData();
    } else {
        setStatus(result?.error || "Failed to start monitoring", true);
    }
}

async function stopCapture() {
    await fetchJSON("/api/stop", { method: "POST" });
    if (pollTimer) { clearInterval(pollTimer); pollTimer = null; }
    setStatus("Monitoring stopped");
    document.getElementById("startBtn").disabled = false;
    document.getElementById("stopBtn").disabled = true;
    setCaptureUI(false);
    await refreshData();
}

async function clearCapture() {
    await fetchJSON("/api/clear", { method: "POST" });
    lastAnalysis = null; lastAlerts = []; lastPackets = [];
    document.getElementById("analysisCard").style.display = "none";
    trafficHistory = Array(42).fill(0);
    updateChart(0);
    updatePosture(null);
    setStatus("Workspace cleared");
    await refreshData();
}

async function refreshData() {
    const data = await fetchJSON("/api/data");
    if (!data) return;

    const c = data.capture;
    if (c) {
        if (c.error) {
            setStatus("Capture error: " + c.error, true);
            document.getElementById("startBtn").disabled = false;
            document.getElementById("stopBtn").disabled = true;
            setCaptureUI(false);
            if (pollTimer) { clearInterval(pollTimer); pollTimer = null; }
        } else if (c.running) {
            setStatus("Capturing • " + (c.packets_captured || 0) + " packets • " + formatDuration(c.duration || 0));
            setCaptureUI(true, c.interface || document.getElementById("interfaceSelect").value, c.duration || 0);
        }
    }

    const s = data.packets || {};
    const total = s.total_packets || 0;
    const pps = Number(s.packets_per_second || 0);
    document.getElementById("stPackets").textContent = total;
    document.getElementById("stRate").textContent = Math.round(pps);
    document.getElementById("stBandwidth").textContent = formatBytes(s.bytes_per_second || 0) + "/s";
    document.getElementById("stHosts").textContent = s.active_hosts || 0;
    document.getElementById("stSources").textContent = s.unique_sources || 0;

    const alerts = data.alerts || [];
    renderAlerts(alerts);
    renderPackets(data.packets_list || []);
    // Graph the real packet rate, not the cumulative packet count
    updateChart(pps);
}

function updateChart(current) {
    trafficHistory.push(Number(current) || 0);
    if (trafficHistory.length > 42) trafficHistory.shift();

    const svgW = 800, svgH = 180, pad = 8;
    const max = Math.max(...trafficHistory, 1);
    const step = (svgW - pad * 2) / (trafficHistory.length - 1);
    const points = trafficHistory.map((v, i) => {
        const x = pad + i * step;
        const y = svgH - pad - (v / max) * (svgH - pad * 2);
        return `${x.toFixed(1)},${y.toFixed(1)}`;
    });

    document.getElementById("chartLine").setAttribute("d", "M " + points.join(" L "));
    document.getElementById("chartArea").setAttribute("d", `M ${pad},${svgH-pad} L ${points.join(" L ")} L ${svgW-pad},${svgH-pad} Z`);
    document.getElementById("chartCurrent").textContent = `${Number(current).toFixed(1)} packets/sec`;
    document.getElementById("chartEmpty").style.display = current ? "none" : "grid";
}

function renderPackets(list) {
    const body = document.getElementById("packetBody");
    lastPackets = list;
    const recent = list.slice(-25).reverse();
    document.getElementById("packetCount").textContent = `${recent.length} shown`;

    if (!recent.length) {
        body.innerHTML = '<tr><td colspan="5" class="empty-row">No packets yet</td></tr>';
        return;
    }

    body.innerHTML = recent.map(p =>
        `<tr><td>${escapeHTML(p.time)}</td><td>${escapeHTML(p.src)}</td><td>${escapeHTML(p.dst)}</td><td class="proto">${escapeHTML(p.proto)}</td><td>${escapeHTML(p.length)}</td></tr>`
    ).join("");
}

function renderAlerts(alerts) {
    lastAlerts = alerts;
    document.getElementById("stAlerts").textContent = alerts.length;
    document.getElementById("navAlertCount").textContent = alerts.length;
    document.getElementById("alertCountChip").textContent = alerts.length;

    const list = document.getElementById("alertList");
    if (!alerts.length) {
        list.innerHTML = '<div class="empty-state"><span>✓</span><p>No alerts yet</p><small>Capture traffic or analyze a CSV.</small></div>';
        document.getElementById("alertDetail").innerHTML = '<div class="detail-empty">Select an alert to inspect evidence and suggested investigation steps.</div>';
        return;
    }

    list.innerHTML = "";
    alerts.forEach((a, i) => {
        const div = document.createElement("div");
        const severity = (a.severity || "medium").toLowerCase();
        div.className = "alert-item severity-" + severity;
        div.innerHTML =
            `<span class="alert-rule">${escapeHTML(a.rule_name)}</span>` +
            `<span class="sev sev-${severity}">${escapeHTML(a.severity)}</span>` +
            `<div class="alert-evidence">${escapeHTML(a.evidence)}</div>`;

        div.onclick = () => {
            document.querySelectorAll(".alert-item").forEach(el => el.classList.remove("selected"));
            div.classList.add("selected");
            showAlertDetail(a);
        };

        list.appendChild(div);
        if (i === 0) {
            div.classList.add("selected");
            showAlertDetail(a);
        }
    });
}

function showAlertDetail(a) {
    const sev = (a.severity || "medium").toLowerCase();
    const when = String(a.timestamp || "").replace("T", " ").slice(0, 19);
    document.getElementById("alertDetail").innerHTML =
        `<h4>${escapeHTML(a.rule_name)} <span class="sev sev-${escapeHTML(sev)}">${escapeHTML(a.severity)}</span></h4>` +
        `<div class="why"><b>Source:</b> ${escapeHTML(a.source || "?")}` +
        (a.destination ? ` → <b>Target:</b> ${escapeHTML(a.destination)}` : "") + `</div>` +
        `<div class="why"><b>Time:</b> ${escapeHTML(when)} · <b>Confidence:</b> ${Number(a.confidence || 0)}%</div>` +
        (a.mitre_technique ? `<div class="why"><b>MITRE ATT&CK:</b> ${escapeHTML(a.mitre_technique)}</div>` : "") +
        (a.windows_matched > 1 ? `<div class="why"><b>Matched in:</b> ${Number(a.windows_matched)} time windows</div>` : "") +
        `<div class="why"><b>Evidence:</b> ${escapeHTML(a.evidence)}</div>` +
        `<div class="why"><b>Why it matters:</b> ${escapeHTML(a.why_it_matters)}</div>` +
        (a.possible_benign_explanations?.length
            ? `<h4>Possible benign causes</h4><ul>${a.possible_benign_explanations.map(s => `<li>${escapeHTML(s)}</li>`).join("")}</ul>` : "") +
        (a.suggested_investigation?.length
            ? `<h4>Suggested investigation</h4><ul>${a.suggested_investigation.map(s => `<li>${escapeHTML(s)}</li>`).join("")}</ul>` : "");
}

async function analyzeCaptured() {
    setStatus("Analyzing captured packets…");
    const data = await fetchJSON("/api/analyze", { method: "POST" });
    if (!data || data.error) {
        setStatus(data?.error || "Analysis failed", true);
        return;
    }
    renderAnalysis(data);
    setStatus("Analysis complete");
}

async function analyzeCsv(input) {
    if (!input.files?.length) return;
    const form = new FormData();
    form.append("file", input.files[0]);
    setStatus("Analyzing CSV…");

    try {
        const res = await fetch("/api/csv/analyze", { method: "POST", body: form });
        const data = await res.json();
        if (!res.ok) {
            setStatus("Error: " + (data.error || res.status), true);
            return;
        }
        renderAnalysis(data);
        setStatus("CSV analysis complete");
    } catch (e) {
        setStatus("CSV request failed", true);
    }
    input.value = "";
}

function renderAnalysis(d) {
    lastAnalysis = d;
    const card = document.getElementById("analysisCard");
    card.style.display = "block";

    document.getElementById("analysisTitle").textContent = "Analysis Results — " + (d.filename || "Captured traffic");

    const score = d.investigation_score || {};
    const total = score.total_score || 0;
    const badge = document.getElementById("scoreBadge");
    badge.className = "score-card" + (total >= 60 ? " high" : total >= 30 ? " mid" : "");
    badge.innerHTML = `<span class="num">${total}</span><span class="lbl">INVESTIGATION SCORE</span>`;

    document.getElementById("analysisMeta").innerHTML =
        `<b>${d.packets_loaded || 0}</b> packets analyzed • <b>${d.unique_sources || 0}</b> sources • ` +
        `<b>${d.unique_destinations || 0}</b> destinations • <b>${d.active_hosts || 0}</b> active hosts • ` +
        `<b>${(d.alerts || []).length}</b> alerts` +
        (d.packets_per_second ? ` • <b>${d.packets_per_second}</b> packets/sec` : "") +
        (d.duration_seconds ? ` • <b>${formatDuration(d.duration_seconds)}</b> duration` : "") + "<br>" +
        (d.avg_packet_length ? `Average packet size: <b>${Math.round(d.avg_packet_length)}</b> bytes` : "") +
        (d.most_active_source ? `<br>Most active source: <b>${escapeHTML(d.most_active_source)}</b>` : "") +
        (d.most_contacted_destination ? ` • Top destination: <b>${escapeHTML(d.most_contacted_destination)}</b>` : "");

    renderTalkers("topSources", d.top_sources || []);
    renderTalkers("topDestinations", d.top_destinations || []);
    renderProtocols(d.protocol_distribution || {});
    renderDevices(d.devices || []);
    renderContributions(score.contributions || []);
    updatePosture(total);

    if (d.alerts?.length) renderAlerts(d.alerts);
    card.scrollIntoView({ behavior: "smooth", block: "start" });
}

function updatePosture(score) {
    const ring = document.getElementById("postureRing");
    const num = document.getElementById("postureScore");
    const label = document.getElementById("postureLabel");
    const text = document.getElementById("postureText");

    if (score === null || score === undefined) {
        ring.style.background = "conic-gradient(var(--track) 0deg 360deg)";
        num.textContent = "—"; label.textContent = "Waiting";
        text.textContent = "Run an analysis to calculate the investigation score.";
        return;
    }

    const value = Math.min(100, Math.max(0, Number(score)));
    const color = value >= 60 ? "var(--red)" : value >= 30 ? "var(--yellow)" : "var(--green)";
    ring.style.background = `conic-gradient(${color} ${value * 3.6}deg,var(--track) ${value * 3.6}deg)`;
    num.textContent = value;
    label.textContent = value >= 60 ? "Elevated" : value >= 30 ? "Watch" : "Normal";
    text.textContent = value >= 60 ? "Multiple signals require investigation." : value >= 30 ? "Some traffic deserves closer review." : "No strong anomaly signal in the analyzed traffic.";
}

function renderTalkers(id, items) {
    const el = document.getElementById(id);
    el.innerHTML = items.length
        ? items.map(it => `<li><span>${escapeHTML(it.ip)}</span><span>${escapeHTML(it.count)}</span></li>`).join("")
        : '<li class="muted">No data</li>';
}

function renderProtocols(dist) {
    const el = document.getElementById("protoDist");
    const entries = Object.entries(dist).sort((a,b) => b[1] - a[1]);
    const total = entries.reduce((sum, e) => sum + e[1], 0) || 1;

    el.innerHTML = entries.length ? entries.map(([proto,count]) => {
        const pct = Math.round((count / total) * 100);
        return `<div class="row"><div class="top"><span>${escapeHTML(proto)}</span><span>${count} (${pct}%)</span></div><div class="bar"><i style="width:${pct}%"></i></div></div>`;
    }).join(("")) : '<div class="muted">No data</div>';
}

function renderDevices(devices) {
    const body = document.getElementById("deviceBody");
    if (!body) return;
    if (!devices || !devices.length) {
        body.innerHTML = '<tr><td colspan="4" class="empty-row">No devices found</td></tr>';
        return;
    }
    body.innerHTML = devices.map(dev =>
        `<tr><td>${escapeHTML(dev.ip)}</td>` +
        `<td>${Number(dev.packets || 0).toLocaleString()}</td>` +
        `<td>${escapeHTML(formatBytes(dev.bytes || 0))}</td>` +
        `<td><span class="risk risk-${escapeHTML(dev.risk || "normal")}">${escapeHTML(dev.risk || "normal")}</span></td></tr>`
    ).join("");
}

function renderContributions(cons) {
    const el = document.getElementById("scoreContributions");
    el.innerHTML = cons.length
        ? cons.map(c => `<div class="con"><b>+${escapeHTML(c.score)}</b>${escapeHTML(c.label)} — ${escapeHTML(c.reason)}</div>`).join("")
        : '<div class="muted">No score contributions — traffic looks normal.</div>';
}

loadInterfaces();
refreshData();


/* ================= Report download ================= */

function toggleReportMenu(e) {
    e.stopPropagation();
    document.getElementById("reportMenu").classList.toggle("open");
}
document.addEventListener("click", () => document.getElementById("reportMenu")?.classList.remove("open"));

function downloadBlob(filename, content, type) {
    const blob = new Blob([content], { type });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url; a.download = filename;
    document.body.appendChild(a); a.click(); a.remove();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
}

function reportStamp() {
    const d = new Date(), p = n => String(n).padStart(2, "0");
    return `${d.getFullYear()}${p(d.getMonth()+1)}${p(d.getDate())}-${p(d.getHours())}${p(d.getMinutes())}${p(d.getSeconds())}`;
}

function reportAlerts(d) {
    return d.alerts?.length ? d.alerts : lastAlerts;
}

async function downloadReport(format) {
    document.getElementById("reportMenu")?.classList.remove("open");

    // No analysis yet? Analyze the captured packets first.
    if (!lastAnalysis) {
        await analyzeCaptured();
    }
    if (!lastAnalysis) {
        setStatus("Nothing to export — capture traffic or import a CSV, then analyze", true);
        return;
    }

    const d = lastAnalysis;
    const base = "netsentinel-report-" + reportStamp();

    try {
        if (format === "json") {
            const payload = { generated_at: new Date().toISOString(), ...d, alerts: reportAlerts(d) };
            downloadBlob(base + ".json", JSON.stringify(payload, null, 2), "application/json");
        } else if (format === "csv") {
            downloadBlob(base + ".csv", buildAlertsCSV(d), "text/csv;charset=utf-8");
        } else {
            downloadBlob(base + ".html", await buildHTMLReport(d), "text/html;charset=utf-8");
        }
    } catch (err) {
        // Never fail silently — surface the exact error in the status pill
        console.error("Report export failed:", err);
        setStatus("Report export failed: " + (err && err.message ? err.message : err), true);
        return;
    }
    setStatus("Report downloaded (" + format.toUpperCase() + ")");
}

function csvCell(v) {
    if (Array.isArray(v)) v = v.join(" | ");
    v = String(v ?? "");
    return /[",\n\r]/.test(v) ? '"' + v.replace(/"/g, '""') + '"' : v;
}

function buildAlertsCSV(d) {
    const head = ["Timestamp", "Rule", "Severity", "Source", "Destination", "Confidence (%)", "MITRE ATT&CK", "Evidence", "Why it matters", "Possible benign explanations", "Suggested investigation"];
    const rows = reportAlerts(d).map(a => [
        a.timestamp, a.rule_name, a.severity, a.source, a.destination,
        a.confidence, a.mitre_technique, a.evidence, a.why_it_matters,
        a.possible_benign_explanations, a.suggested_investigation
    ].map(csvCell).join(","));
    return "\ufeff" + [head.join(","), ...rows].join("\r\n");
}

async function buildHTMLReport(d) {
    const e = escapeHTML;
    const alerts = reportAlerts(d);
    const score = d.investigation_score || {};
    const total = Math.min(100, Math.max(0, Number(score.total_score) || 0));
    const level = total >= 60 ? "Elevated" : total >= 30 ? "Watch" : "Normal";
    const color = total >= 60 ? "var(--red)" : total >= 30 ? "var(--yellow)" : "var(--green)";
    const cls = total >= 60 ? " high" : total >= 30 ? " mid" : "";
    const summaryText = total >= 60 ? "Multiple signals require investigation." : total >= 30 ? "Some traffic deserves closer review." : "No strong anomaly signal in the analyzed traffic.";
    const generated = new Date().toLocaleString();
    const theme = document.documentElement.getAttribute("data-theme") || "light";
    const source = d.filename || "Live capture";

    // Reuse the dashboard's own stylesheet so the report looks identical
    let css = "";
    try { const r = await fetch("/styles.css"); if (r.ok) css = await r.text(); } catch (err) {}
    css = css.replace(/<\/style/gi, "<\\/style");

    const dist = d.protocol_distribution || {};
    const pc = k => Object.entries(dist).find(([p]) => p.toUpperCase() === k)?.[1] || 0;

    const talkers = items => items?.length
        ? items.map(i => `<li><span>${e(i.ip)}</span><span>${e(i.count)}</span></li>`).join("")
        : '<li class="muted">No data</li>';

    const protoEntries = Object.entries(dist).sort((a, b) => b[1] - a[1]);
    const protoTotal = protoEntries.reduce((t, x) => t + x[1], 0) || 1;
    const protoHTML = protoEntries.length ? protoEntries.map(([p, c]) => {
        const pct = Math.round(c / protoTotal * 100);
        return `<div class="row"><div class="top"><span>${e(p)}</span><span>${c} (${pct}%)</span></div><div class="bar"><i style="width:${pct}%"></i></div></div>`;
    }).join("") : '<div class="muted">No data</div>';

    const contribs = (score.contributions || []).length
        ? score.contributions.map(c => `<div class="con"><b>+${e(c.score)}</b>${e(c.label)} — ${e(c.reason)}</div>`).join("")
        : '<div class="muted">No score contributions — traffic looks normal.</div>';

    const alertItems = alerts.length ? alerts.map((a, i) => {
        const sev = (a.severity || "medium").toLowerCase();
        return `<div class="alert-item severity-${e(sev)}" data-i="${i}"><span class="alert-rule">${e(a.rule_name)}</span><span class="sev sev-${e(sev)}">${e(a.severity)}</span><div class="alert-evidence">${e(a.evidence)}</div></div>`;
    }).join("") : '<div class="empty-state"><span>✓</span><p>No alerts were raised</p><small>Nothing in this traffic matched a detection rule.</small></div>';

    const pkts = (!d.filename && lastPackets.length) ? lastPackets.slice(-100).reverse() : [];
    const packetsSection = pkts.length ? `
    <section class="panel packets-panel" id="packetsPanel">
        <div class="panel-title"><h2>Recent packets</h2><span class="mini-status">latest ${pkts.length}</span></div>
        <div class="table-wrap"><table>
            <thead><tr><th>Time</th><th>Source</th><th>Destination</th><th>Protocol</th><th>Length</th></tr></thead>
            <tbody>${pkts.map(p => `<tr><td>${e(p.time)}</td><td>${e(p.src)}</td><td>${e(p.dst)}</td><td class="proto">${e(p.proto)}</td><td>${e(p.length)}</td></tr>`).join("")}</tbody>
        </table></div>
    </section>` : "";

    const devicesSection = (d.devices && d.devices.length) ? `
    <section class="panel">
        <div class="panel-title"><h2>Network devices</h2><span class="mini-status">${d.devices.length} observed</span></div>
        <div class="table-wrap devices-wrap"><table class="devices-table">
            <thead><tr><th>IP address</th><th>Packets</th><th>Bytes</th><th>Risk</th></tr></thead>
            <tbody>${d.devices.map(x => `<tr><td>${e(x.ip)}</td><td>${Number(x.packets || 0).toLocaleString()}</td><td>${e(formatBytes(x.bytes || 0))}</td><td><span class="risk risk-${e(x.risk || "normal")}">${e(x.risk || "normal")}</span></td></tr>`).join("")}</tbody>
        </table></div>
    </section>` : "";

    const metaHTML =
        `<b>${e(d.packets_loaded || 0)}</b> packets analyzed • <b>${e(d.unique_sources || 0)}</b> sources • <b>${e(d.unique_destinations || 0)}</b> destinations • <b>${e(d.active_hosts || 0)}</b> active hosts • <b>${alerts.length}</b> alerts` +
        (d.packets_per_second ? ` • <b>${e(d.packets_per_second)}</b> packets/sec` : "") +
        (d.duration_seconds ? ` • <b>${e(formatDuration(d.duration_seconds))}</b> duration` : "") + "<br>" +
        (d.avg_packet_length ? `Average packet size: <b>${Math.round(d.avg_packet_length)}</b> bytes` : "") +
        (d.most_active_source ? `<br>Most active source: <b>${e(d.most_active_source)}</b>` : "") +
        (d.most_contacted_destination ? ` • Top destination: <b>${e(d.most_contacted_destination)}</b>` : "");

    const dataJSON = JSON.stringify(alerts).replace(/</g, "\\u003c");

    const inline = String.raw`
var A=JSON.parse(document.getElementById('alert-data').textContent);
function esc(s){return String(s==null?'':s).replace(/[&<>"']/g,function(c){return {'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#039;'}[c]})}
function ul(a){return a&&a.length?'<ul>'+a.map(function(s){return '<li>'+esc(s)+'</li>'}).join('')+'</ul>':''}
function show(i){
  var a=A[i]; if(!a) return;
  document.querySelectorAll('.alert-item').forEach(function(el){el.classList.toggle('selected',+el.dataset.i===i)});
  document.getElementById('alertDetail').innerHTML=
    '<h4>'+esc(a.rule_name)+' <span class="sev sev-'+esc(a.severity||'medium').toLowerCase()+'">'+esc(a.severity)+'</span></h4>'+
    '<div class="why"><b>Source:</b> '+esc(a.source||'?')+(a.destination?' → <b>Target:</b> '+esc(a.destination):'')+'</div>'+
    '<div class="why"><b>Time:</b> '+esc(String(a.timestamp||'').replace('T',' ').slice(0,19))+' · <b>Confidence:</b> '+Number(a.confidence||0)+'%</div>'+
    (a.mitre_technique?'<div class="why"><b>MITRE ATT&amp;CK:</b> '+esc(a.mitre_technique)+'</div>':'')+
    '<div class="why"><b>Evidence:</b> '+esc(a.evidence)+'</div>'+
    '<div class="why"><b>Why it matters:</b> '+esc(a.why_it_matters)+'</div>'+
    (a.possible_benign_explanations&&a.possible_benign_explanations.length?'<h4>Possible benign causes</h4>'+ul(a.possible_benign_explanations):'')+
    (a.suggested_investigation&&a.suggested_investigation.length?'<h4>Suggested investigation</h4>'+ul(a.suggested_investigation):'');
}
document.getElementById('alertList').addEventListener('click',function(ev){var it=ev.target.closest('.alert-item'); if(it) show(+it.dataset.i);});
if(A.length) show(0);
var tb=document.getElementById('themeBtn');
function setT(t){document.documentElement.setAttribute('data-theme',t);tb.textContent=t==='dark'?'\u2600':'\u263E';}
tb.onclick=function(){setT(document.documentElement.getAttribute('data-theme')==='dark'?'light':'dark');};
setT(document.documentElement.getAttribute('data-theme')||'light');
`;

    return `<!DOCTYPE html>
<html lang="en" data-theme="${e(theme)}"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>NetSentinel Report — ${e(source)}</title>
<style>${css}
.topbar{position:static}
@media print{.topbar .top-actions,.nav{display:none}.main{padding-top:10px}.panel,.step,.metric-card{box-shadow:none;break-inside:avoid}.alert-list,.table-wrap{max-height:none!important;overflow:visible!important}}
</style></head><body>
<header class="topbar"><div class="topbar-in">
    <a class="brand" href="#overview">
        <svg width="28" height="28" viewBox="0 0 28 28" aria-hidden="true"><rect width="28" height="28" rx="8" fill="var(--accent)"/><path d="M6 15h4l2.5-6 3.5 11 2.5-5H22" fill="none" stroke="#fff" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/></svg>
        <span>NetSentinel</span>
    </a>
    <nav class="nav">
        <a class="nav-item active" href="#overview">Summary</a>
        <a class="nav-item" href="#analysisCard">Analysis</a>
        <a class="nav-item" href="#alertsPanel">Alerts <b>${alerts.length}</b></a>
        ${pkts.length ? '<a class="nav-item" href="#packetsPanel">Packets</a>' : ""}
    </nav>
    <div class="top-actions">
        <span class="status-pill"><i></i> Report · ${e(generated)}</span>
        <button class="icon-btn" id="themeBtn" title="Switch theme" aria-label="Switch theme">☾</button>
    </div>
</div></header>

<main class="main">
    <section id="overview" class="hero">
        <div class="hero-text">
            <h1>Network analysis report</h1>
            <p>Source: ${e(source)}. Generated ${e(generated)}. ${e(summaryText)}</p>
        </div>
        <div class="live-card">
            <span class="live-dot" style="background:${color}"></span>
            <div><strong>${e(level)} · score ${total}</strong><span>${alerts.length} alert${alerts.length === 1 ? "" : "s"} raised</span></div>
        </div>
    </section>

    <section class="stats-grid">
        <article class="metric-card"><span>Packets</span><strong>${e(d.packets_loaded || 0)}</strong><small>Analyzed</small></article>
        <article class="metric-card"><span>Packets/sec</span><strong>${e(d.packets_per_second || 0)}</strong><small>Average rate</small></article>
        <article class="metric-card"><span>Bandwidth</span><strong>${e(formatBytes(d.bytes_per_second || 0))}/s</strong><small>Average throughput</small></article>
        <article class="metric-card"><span>Active hosts</span><strong>${e(d.active_hosts || 0)}</strong><small>Unique devices</small></article>
        <article class="metric-card"><span>Sources</span><strong>${e(d.unique_sources || 0)}</strong><small>Unique source IPs</small></article>
        <article class="metric-card alert-metric"><span>Alerts</span><strong>${alerts.length}</strong><small>Detected signals</small></article>
    </section>

    <section class="visual-grid">
        <article class="panel">
            <div class="panel-title"><h2>Score breakdown</h2></div>
            <div class="contributions">${contribs}</div>
        </article>
        <article class="panel posture-panel">
            <div class="panel-title"><h2>Security state</h2></div>
            <div class="posture-ring" style="background:conic-gradient(${color} ${total * 3.6}deg,var(--track) ${total * 3.6}deg)">
                <div><strong>${total}</strong><span>${e(level)}</span></div>
            </div>
            <p>${e(summaryText)}</p>
        </article>
    </section>

    <section class="panel analysis-panel" id="analysisCard">
        <div class="panel-title"><h2>Analysis results — ${e(source)}</h2></div>
        <div class="analysis-summary">
            <div class="score-card${cls}"><span class="num">${total}</span><span class="lbl">Investigation score</span></div>
            <div class="analysis-meta">${metaHTML}</div>
        </div>
        <div class="analysis-grid">
            <div class="data-block"><h3>Top sources</h3><ul class="talkers">${talkers(d.top_sources)}</ul></div>
            <div class="data-block"><h3>Top destinations</h3><ul class="talkers">${talkers(d.top_destinations)}</ul></div>
            <div class="data-block"><h3>Protocol distribution</h3><div class="proto-dist">${protoHTML}</div></div>
        </div>
    </section>

    <section class="two-col">
        <article class="panel" id="alertsPanel">
            <div class="panel-title"><h2>Alerts</h2><span class="count-chip">${alerts.length}</span></div>
            <div class="alert-list" id="alertList">${alertItems}</div>
        </article>
        <article class="panel">
            <div class="panel-title"><h2>Alert detail</h2></div>
            <div id="alertDetail" class="detail-empty">No alert selected.</div>
        </article>
    </section>
    ${devicesSection}
    ${packetsSection}
    <footer class="footer"><span>NetSentinel · local network anomaly detection</span><span>Generated locally — data never left this machine</span></footer>
</main>
<script type="application/json" id="alert-data">${dataJSON}</script>
<script>${inline}</script>
</body></html>`;
}


/* ================= Theme + navigation ================= */

function applyTheme(t) {
    document.documentElement.setAttribute("data-theme", t);
    const b = document.getElementById("themeBtn");
    if (b) b.textContent = t === "dark" ? "☀" : "☾";
}
function toggleTheme() {
    const next = document.documentElement.getAttribute("data-theme") === "dark" ? "light" : "dark";
    applyTheme(next);
    try { localStorage.setItem("ns-theme", next); } catch (e) {}
}
(function initTheme() {
    let t = "light";
    try { t = localStorage.getItem("ns-theme") || (matchMedia("(prefers-color-scheme: dark)").matches ? "dark" : "light"); } catch (e) {}
    applyTheme(t);
})();

// Analysis link: only meaningful once results exist
document.getElementById("navAnalysis").addEventListener("click", e => {
    if (!lastAnalysis) {
        e.preventDefault();
        setStatus("Run Analyze first to see results", true);
    }
});

// Highlight the nav item for the section in view
(function scrollSpy() {
    const links = [...document.querySelectorAll(".nav-item")];
    const map = new Map(links.map(l => [l.getAttribute("href").slice(1), l]));
    const io = new IntersectionObserver(entries => {
        entries.forEach(en => {
            if (en.isIntersecting && map.has(en.target.id)) {
                links.forEach(l => l.classList.remove("active"));
                map.get(en.target.id).classList.add("active");
            }
        });
    }, { rootMargin: "-30% 0px -60% 0px" });
    map.forEach((_, id) => { const el = document.getElementById(id); if (el) io.observe(el); });
})();
