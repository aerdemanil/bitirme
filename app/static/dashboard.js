/**
 * dashboard.js
 * ─────────────────────────────────────────────────────────
 * ADS Guardian — Gerçek Zamanlı Dashboard Frontend
 *
 * Bağımlılıklar: Chart.js 4, Socket.IO 4
 * ─────────────────────────────────────────────────────────
 */

"use strict";

// ═══════════════════════════════════════════
// STATE
// ═══════════════════════════════════════════
const state = {
  paused:       false,
  logFilter:    "all",
  logCount:     0,
  attackCount:  0,
  prevRequests: 0,
  prevAttacks:  0,
};

// ═══════════════════════════════════════════
// DOM HELPERS
// ═══════════════════════════════════════════
const $  = (sel) => document.querySelector(sel);
const $$ = (sel) => document.querySelectorAll(sel);

function setText(id, val) {
  const el = document.getElementById(id);
  if (el) el.textContent = val;
}

function animateNumber(id, newVal) {
  const el = document.getElementById(id);
  if (!el) return;
  const old = parseInt(el.textContent.replace(/,/g, "")) || 0;
  if (old === newVal) return;
  el.textContent = newVal.toLocaleString();
  el.classList.remove("pop");
  void el.offsetWidth;
  el.classList.add("pop");
}

// ═══════════════════════════════════════════
// NAVIGATION
// ═══════════════════════════════════════════
const SECTIONS = {
  overview: { section: "section-overview", nav: "nav-overview", title: "Genel Bakış",  sub: "Overview" },
  attacks:  { section: "section-attacks",  nav: "nav-attacks",  title: "Saldırılar",   sub: "Attacks" },
  logs:     { section: "section-logs",     nav: "nav-logs",     title: "Canlı Loglar", sub: "Live Logs" },
  test:     { section: "section-test",     nav: "nav-test",     title: "Sistem Testi", sub: "System Test" },
  ai:       { section: "section-ai",       nav: "nav-ai",       title: "AI Asistan",   sub: "AI Assistant" },
};

function navigate(key) {
  Object.values(SECTIONS).forEach(({ section, nav }) => {
    document.getElementById(section)?.classList.remove("active");
    document.getElementById(nav)?.classList.remove("active");
  });
  const cfg = SECTIONS[key];
  if (!cfg) return;
  document.getElementById(cfg.section)?.classList.add("active");
  document.getElementById(cfg.nav)?.classList.add("active");
  setText("page-title",     cfg.title);
  setText("breadcrumb-sub", cfg.sub);
  if (key === "ai") aiLoadIpRisks();
}

$$(".nav-item").forEach(link => {
  link.addEventListener("click", e => {
    e.preventDefault();
    const href = link.getAttribute("href").replace("#", "");
    navigate(href);
  });
});

// ═══════════════════════════════════════════
// CLOCK
// ═══════════════════════════════════════════
function updateClock() {
  setText("header-time", new Date().toLocaleTimeString("tr-TR"));
}
updateClock();
setInterval(updateClock, 1000);

// ═══════════════════════════════════════════
// UPTIME FORMATTER
// ═══════════════════════════════════════════
function formatUptime(secs) {
  const h = String(Math.floor(secs / 3600)).padStart(2, "0");
  const m = String(Math.floor((secs % 3600) / 60)).padStart(2, "0");
  const s = String(secs % 60).padStart(2, "0");
  return `${h}:${m}:${s}`;
}

// ═══════════════════════════════════════════
// CHARTS
// ═══════════════════════════════════════════
Chart.defaults.color = "#94a3b8";
Chart.defaults.borderColor = "rgba(99,179,237,0.08)";

// ── Time Series ──
const tsCtx = document.getElementById("chart-timeseries").getContext("2d");
const tsChart = new Chart(tsCtx, {
  type: "line",
  data: {
    labels: [],
    datasets: [
      {
        label: "İstekler",
        data: [],
        borderColor: "#3b82f6",
        backgroundColor: "rgba(59,130,246,0.08)",
        fill: true,
        tension: 0.4,
        pointRadius: 3,
        pointBackgroundColor: "#3b82f6",
      },
      {
        label: "Saldırılar",
        data: [],
        borderColor: "#ef4444",
        backgroundColor: "rgba(239,68,68,0.08)",
        fill: true,
        tension: 0.4,
        pointRadius: 3,
        pointBackgroundColor: "#ef4444",
      },
    ],
  },
  options: {
    responsive: true,
    maintainAspectRatio: false,
    animation: { duration: 400 },
    plugins: { legend: { display: false } },
    scales: {
      x: { grid: { color: "rgba(99,179,237,0.06)" }, ticks: { maxTicksLimit: 10, font: { size: 11 } } },
      y: { grid: { color: "rgba(99,179,237,0.06)" }, ticks: { font: { size: 11 } }, beginAtZero: true },
    },
  },
});

// ── Doughnut ──
const ATTACK_COLORS = {
  dos:           "#ef4444",
  brute_force:   "#f97316",
  sql_injection: "#8b5cf6",
};
const ATTACK_LABELS = {
  dos:           "DoS",
  brute_force:   "Brute Force",
  sql_injection: "SQL Injection",
};

const doCtx = document.getElementById("chart-attack-types").getContext("2d");
const doChart = new Chart(doCtx, {
  type: "doughnut",
  data: { labels: [], datasets: [{ data: [], backgroundColor: [], borderWidth: 2, borderColor: "#0d1728" }] },
  options: {
    responsive: true,
    maintainAspectRatio: false,
    cutout: "68%",
    animation: { duration: 500 },
    plugins: {
      legend: {
        position: "bottom",
        labels: { font: { size: 11 }, padding: 14, usePointStyle: true, pointStyleWidth: 8 },
      },
    },
  },
});

function updateDoughnut(attackTypes) {
  const keys = Object.keys(attackTypes);
  const vals = Object.values(attackTypes);
  const total = vals.reduce((a, b) => a + b, 0);

  doChart.data.labels   = keys.map(k => ATTACK_LABELS[k] || k);
  doChart.data.datasets[0].data = vals;
  doChart.data.datasets[0].backgroundColor = keys.map(k => ATTACK_COLORS[k] || "#64748b");
  doChart.update();

  setText("doughnut-total", total.toLocaleString());
}

function updateTimeSeries(timeseries) {
  if (!timeseries?.length) return;
  tsChart.data.labels              = timeseries.map(t => t.minute);
  tsChart.data.datasets[0].data   = timeseries.map(t => t.requests);
  tsChart.data.datasets[1].data   = timeseries.map(t => t.attacks);
  tsChart.update();
}

// ═══════════════════════════════════════════
// THREAT LEVEL
// ═══════════════════════════════════════════
function updateThreatLevel(totalReq, totalAttacks) {
  const badge = document.getElementById("threat-badge");
  if (!badge) return;
  const ratio = totalReq > 0 ? totalAttacks / totalReq : 0;
  badge.className = "threat-badge";
  if (ratio > 0.30)      { badge.textContent = "KRİTİK"; badge.classList.add("critical"); }
  else if (ratio > 0.10) { badge.textContent = "YÜKSEK";  badge.classList.add("high"); }
  else if (ratio > 0.02) { badge.textContent = "ORTA";    badge.classList.add("medium"); }
  else                   { badge.textContent = "DÜŞÜK"; }
}

// ═══════════════════════════════════════════
// ACTIVE SESSIONS TABLE
// ═══════════════════════════════════════════
function renderActiveSessions(sessions) {
  const tbody = document.getElementById("active-sessions-body");
  const count = document.getElementById("active-sessions-count");
  if (!tbody) return;

  setText("stat-active-attacks", sessions.length);
  if (count) count.textContent = `${sessions.length} oturum`;

  if (sessions.length === 0) {
    tbody.innerHTML = `<tr class="empty-row"><td colspan="7">Aktif saldırı oturumu yok</td></tr>`;
    return;
  }

  tbody.innerHTML = sessions.map(s => `
    <tr class="row-attack">
      <td style="font-family:var(--font-mono);color:var(--accent-cyan)">${s.ip}</td>
      <td>${attackPill(s.detector)}</td>
      <td>${s.duration}s</td>
      <td>${s.total_req.toLocaleString()}</td>
      <td>${s.peak_rpm}</td>
      <td>${confBadge(s.peak_conf)}</td>
      <td><span class="pill pill--active">● AKTİF</span></td>
    </tr>
  `).join("");
}

// ═══════════════════════════════════════════
// ATTACKS TABLE
// ═══════════════════════════════════════════
let _attackRows = [];

function attackPill(type) {
  const cls = {
    dos: "pill--dos", brute_force: "pill--brute",
    sql_injection: "pill--sqli",
  }[type] || "pill--normal";
  const label = ATTACK_LABELS[type] || type.toUpperCase();
  return `<span class="pill ${cls}">${label}</span>`;
}

function confBadge(conf) {
  const pct = Math.round(conf * 100);
  const color = conf > 0.80 ? "#ef4444" : conf > 0.55 ? "#f97316" : "#eab308";
  return `
    <div class="conf-bar-wrap">
      <div class="conf-bar"><div class="conf-bar-fill" style="width:${pct}%;background:${color}"></div></div>
      <span style="font-size:11px;color:${color};font-family:var(--font-mono)">${pct}%</span>
    </div>`;
}


function statusColor(code) {
  if (code >= 500) return "status-5xx";
  if (code >= 400) return "status-4xx";
  if (code >= 300) return "status-3xx";
  return "status-2xx";
}

function renderAttackRow(attack) {
  const attackJson = encodeURIComponent(JSON.stringify(attack));
  return `
    <tr class="row-attack" data-ip="${attack.ip}" data-type="${attack.type}">
      <td style="font-family:var(--font-mono);color:var(--text-muted)">${attack.time}</td>
      <td style="font-family:var(--font-mono);color:var(--accent-cyan)">${attack.ip}</td>
      <td>${attackPill(attack.type)}</td>
      <td>${confBadge(attack.confidence)}</td>
      <td style="color:var(--text-secondary);max-width:200px;overflow:hidden;text-overflow:ellipsis">${attack.path}</td>
      <td style="color:var(--accent-blue)">${attack.method}</td>
      <td class="${statusColor(attack.status)}">${attack.status}</td>
      <td>${attack.rpm}</td>
      <td><button class="ai-analyze-btn" onclick="openAiModal(JSON.parse(decodeURIComponent('${attackJson}')))" title="AI ile Analiz Et">🤖 AI</button></td>
    </tr>`;
}

// AI sekmesine yönlendir ve saldırıyı chat'e ekle
async function openAiModal(attack) {
  navigate("ai");
  const label = `${attack.type} saldırısı analizi — IP: ${attack.ip}, Güven: ${Math.round(attack.confidence * 100)}%`;
  aiAppendMessage("user", label);
  const thinking = aiAppendMessage("thinking", "Analiz ediliyor...");
  try {
    const resp = await fetch("/api/ai/analyze", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ attack })
    });
    const data = await resp.json();
    thinking.remove();
    aiAppendMessage("bot", data.analysis || data.error || "Yanıt alınamadı.");
  } catch (e) {
    thinking.remove();
    aiAppendMessage("bot", "Bağlantı hatası: " + e.message);
  }
}

function prependAttack(attack) {
  _attackRows.unshift(attack);
  if (_attackRows.length > 200) _attackRows.pop();

  const tbody = document.getElementById("attacks-body");
  if (!tbody) return;

  const search = $("#attack-search")?.value.toLowerCase() || "";
  if (search && !attack.ip.includes(search) && !attack.type.includes(search)) return;

  const emptyRow = tbody.querySelector(".empty-row");
  if (emptyRow) emptyRow.remove();

  tbody.insertAdjacentHTML("afterbegin", renderAttackRow(attack));
  // Trim DOM
  while (tbody.children.length > 100) tbody.removeChild(tbody.lastChild);

  // Badge update
  state.attackCount++;
  const badge = document.getElementById("attack-badge");
  if (badge) badge.textContent = state.attackCount;
}

// ─── Search filter ───
document.getElementById("attack-search")?.addEventListener("input", function () {
  const q = this.value.toLowerCase();
  const tbody = document.getElementById("attacks-body");
  if (!tbody) return;
  $$(".row-attack", tbody).forEach(tr => {
    const ip   = tr.dataset.ip   || "";
    const type = tr.dataset.type || "";
    tr.style.display = (!q || ip.includes(q) || type.includes(q)) ? "" : "none";
  });
});

// ─── Clear attacks ───
document.getElementById("clear-attacks-btn")?.addEventListener("click", () => {
  _attackRows = [];
  const tbody = document.getElementById("attacks-body");
  if (tbody) tbody.innerHTML = `<tr class="empty-row"><td colspan="8">Henüz saldırı tespit edilmedi</td></tr>`;
});

// ═══════════════════════════════════════════
// LOG STREAM
// ═══════════════════════════════════════════
const logStream = document.getElementById("log-stream");
const autoScrollToggle = document.getElementById("auto-scroll-toggle");

function appendLog(entry) {
  if (state.paused) return;

  state.logCount++;
  setText("log-stream-count", `${state.logCount.toLocaleString()} satır`);

  const isAttack = entry.type === "attack";
  const hide     = state.logFilter === "attack"  && !isAttack
                || state.logFilter === "normal"  && isAttack;

  const statusCls = statusColor(entry.status);
  const tagHtml   = isAttack
    ? `<span class="pill pill--${entry.detector?.replace("_", "-") || "dos"}" style="font-size:10px;padding:2px 7px">${ATTACK_LABELS[entry.detector] || entry.detector}</span>`
    : "";

  const scoresHtml = isAttack && entry.confidence != null
    ? (() => {
        const pct = Math.round(entry.confidence * 100);
        const color = entry.confidence > 0.80 ? "#ef4444" : entry.confidence > 0.55 ? "#f97316" : "#eab308";
        return `<span class="log-scores" style="display:inline-flex;align-items:center;gap:4px;margin-left:4px"><div class="conf-bar" style="width:40px"><div class="conf-bar-fill" style="width:${pct}%;background:${color}"></div></div><span style="color:${color};font-family:var(--font-mono);font-size:9px">${pct}%</span></span>`;
      })()
    : "";

  const div = document.createElement("div");
  div.className = `log-line${isAttack ? " attack" : ""}${hide ? " hidden" : ""}`;
  div.dataset.type = entry.type;
  div.dataset.entry = JSON.stringify({
    time: entry.time, ip: entry.ip, method: entry.method,
    status: entry.status, path: entry.path,
    type: entry.type, detector: entry.detector || null
  });
  div.innerHTML = `
    <span class="log-time">${entry.time}</span>
    <span class="log-ip">${entry.ip}</span>
    <span class="log-method">${entry.method}</span>
    <span class="log-status ${statusCls}">${entry.status}</span>
    <span class="log-path">${entry.path}</span>
    <span class="log-tag">${tagHtml}${scoresHtml}</span>`;

  div.addEventListener("click", () => logToggleSelect(div));

  logStream.appendChild(div);

  while (logStream.children.length > 5000) logStream.removeChild(logStream.firstChild);

  // Auto-scroll
  if (autoScrollToggle?.checked) {
    logStream.scrollTop = logStream.scrollHeight;
  }
}

// ─── Log filter buttons ───
$$(".filter-btn").forEach(btn => {
  btn.addEventListener("click", () => {
    $$(".filter-btn").forEach(b => b.classList.remove("active"));
    btn.classList.add("active");
    state.logFilter = btn.dataset.filter;

    $$(".log-line").forEach(el => {
      const type = el.dataset.type || "normal";
      el.classList.toggle(
        "hidden",
        state.logFilter !== "all" && el.dataset.type !== state.logFilter
      );
    });

    const visible = $$(".log-line:not(.hidden)").length;
    setText("log-stream-count", `${visible.toLocaleString()} satır`);
  });
});

// ─── Clear logs ───
document.getElementById("clear-logs-btn")?.addEventListener("click", () => {
  if (logStream) logStream.innerHTML = "";
  state.logCount = 0;
  setText("log-stream-count", "0 satır");
});

// ═══════════════════════════════════════════
// PAUSE BUTTON
// ═══════════════════════════════════════════
const pauseBtn = document.getElementById("pause-btn");
pauseBtn?.addEventListener("click", () => {
  state.paused = !state.paused;
  const blink = $(".blink-dot");
  if (state.paused) {
    pauseBtn.title = "Devam et";
    if (blink) { blink.style.background = "var(--accent-orange)"; blink.style.boxShadow = "0 0 6px var(--accent-orange)"; }
  } else {
    pauseBtn.title = "Log akışını durdur";
    if (blink) { blink.style.background = ""; blink.style.boxShadow = ""; }
  }
});

// ═══════════════════════════════════════════
// TOAST NOTIFICATIONS
// ═══════════════════════════════════════════
function showToast(title, msg, type = "info") {
  const icons = { attack: "🚨", info: "ℹ️", success: "✅", error: "❌" };
  const container = document.getElementById("toast-container");
  if (!container) return;

  const el = document.createElement("div");
  el.className = `toast${type === "attack" ? " attack" : ""}`;
  el.innerHTML = `
    <span class="toast-icon">${icons[type] || "ℹ️"}</span>
    <div class="toast-body">
      <div class="toast-title">${title}</div>
      <div class="toast-msg">${msg}</div>
    </div>`;
  container.appendChild(el);
  setTimeout(() => el.remove(), 5000);
}

// ═══════════════════════════════════════════
// ATTACK MODAL
// ═══════════════════════════════════════════
const modal     = document.getElementById("attack-modal");
const modalBody = document.getElementById("modal-body");

function showAttackModal(attack) {
  if (!modal || !modalBody) return;
  setText("modal-title", `🚨 ${(ATTACK_LABELS[attack.type] || attack.type).toUpperCase()} SALDIRISI TESPİT EDİLDİ`);
  modalBody.innerHTML = `
    <div class="modal-row"><span>Kaynak IP</span><span>${attack.ip}</span></div>
    <div class="modal-row"><span>Saldırı Türü</span><span>${ATTACK_LABELS[attack.type] || attack.type}</span></div>
    <div class="modal-row"><span>Güven Skoru</span><span>${Math.round(attack.confidence * 100)}%</span></div>
    <div class="modal-row"><span>Hedef Yol</span><span>${attack.path}</span></div>
    <div class="modal-row"><span>HTTP Metodu</span><span>${attack.method}</span></div>
    <div class="modal-row"><span>Durum Kodu</span><span>${attack.status}</span></div>
    <div class="modal-row"><span>İstek/dk (RPM)</span><span>${attack.rpm}</span></div>
    <div class="modal-row"><span>Tespit Zamanı</span><span>${attack.time}</span></div>`;
  modal.style.display = "flex";
  setTimeout(() => { modal.style.display = "none"; }, 8000);
}

document.getElementById("modal-close")?.addEventListener("click", () => {
  if (modal) modal.style.display = "none";
});
modal?.addEventListener("click", e => {
  if (e.target === modal) modal.style.display = "none";
});

// ═══════════════════════════════════════════
// SOCKET.IO
// ═══════════════════════════════════════════
const socket = io({ transports: ["websocket", "polling"] });

function setConnectionState(connected) {
  const dot  = document.getElementById("status-dot");
  const text = document.getElementById("status-text");
  if (dot)  { dot.className  = `status-dot ${connected ? "connected" : "error"}`; }
  if (text) { text.textContent = connected ? "Bağlı" : "Bağlantı Kesildi"; }
}

socket.on("connect",    () => setConnectionState(true));
socket.on("disconnect", () => setConnectionState(false));

// ── Initial data load ──
socket.on("init", (data) => {
  updateStats(data.stats, data.attack_types, data.active_attacks || []);
  updateTimeSeries(data.timeseries);
  (data.recent_logs || []).forEach(appendLog);
  (data.recent_attacks || []).forEach(prependAttack);
});

// ── Periodic stats ──
socket.on("stats", (data) => {
  updateStats(data.stats, data.attack_types, data.active_attacks || []);
  updateTimeSeries(data.timeseries);
});

// ── Real-time log line ──
socket.on("log", appendLog);

// ── Real-time attack ──
socket.on("attack", (attack) => {
  prependAttack(attack);
  showToast(
    `${ATTACK_LABELS[attack.type] || attack.type} Tespiti`,
    `IP: ${attack.ip} — Güven: ${Math.round(attack.confidence * 100)}%`,
    "attack"
  );
});

// ── Uptime ──
socket.on("uptime", ({ seconds }) => {
  setText("uptime-display", formatUptime(seconds));
});

// ── System messages ──
socket.on("system", ({ level, message }) => {
  showToast("Sistem", message, level === "error" ? "error" : "info");
});

// ═══════════════════════════════════════════
// UPDATE STATS
// ═══════════════════════════════════════════
function updateStats(stats, attackTypes, activeSessions) {
  animateNumber("stat-total-req",     stats.total_requests);
  animateNumber("stat-total-attacks", stats.total_attacks);
  animateNumber("stat-parse-errors",  stats.parse_errors);

  // Trend indicators
  const reqDelta     = stats.total_requests - state.prevRequests;
  const attackDelta  = stats.total_attacks  - state.prevAttacks;
  state.prevRequests = stats.total_requests;
  state.prevAttacks  = stats.total_attacks;

  const trendReq = document.getElementById("trend-requests");
  const trendAtk = document.getElementById("trend-attacks");
  if (trendReq) trendReq.textContent = reqDelta > 0 ? `+${reqDelta}` : "—";
  if (trendAtk && attackDelta > 0) { trendAtk.textContent = `+${attackDelta}`; trendAtk.classList.add("danger"); }

  updateThreatLevel(stats.total_requests, stats.total_attacks);
  updateDoughnut(attackTypes);
  renderActiveSessions(activeSessions);
}

// ═══════════════════════════════════════════
// PERIODIC STATS REFRESH (fallback REST API)
// ═══════════════════════════════════════════
async function fetchStats() {
  try {
    const res  = await fetch("/api/stats");
    const data = await res.json();
    updateStats(data.stats, data.attack_types, data.active_attacks);
    updateTimeSeries(data.timeseries);
  } catch (_) { /* ignore — socket.io will provide data */ }
}
setInterval(fetchStats, 5000);

// ═══════════════════════════════════════════
// SISTEM TESTI
// ═══════════════════════════════════════════
const TEST_TYPE_NAMES = {
  dos:           "DoS",
  brute_force:   "Brute Force",
  sql_injection: "SQL Injection",
};

function boolPill(val, expected) {
  if (val === null || val === undefined) return `<span class="pill pill--normal">HATA</span>`;
  const label = val ? "TESPİT EDİLDİ" : "TEMİZ";
  const cls   = val ? "pill--dos" : "pill--normal";
  return `<span class="pill ${cls}">${label}</span>`;
}

function expectedPill(val) {
  return val
    ? `<span class="pill pill--dos" style="opacity:.65">Saldırı</span>`
    : `<span class="pill pill--normal" style="opacity:.65">Temiz</span>`;
}

function renderTestResults(results) {
  const tbody = document.getElementById("test-results-body");
  const count = document.getElementById("test-result-count");
  if (!tbody) return;

  if (!results.length) {
    tbody.innerHTML = `<tr class="empty-row"><td colspan="6">Sonuç bulunamadı.</td></tr>`;
    return;
  }

  const passed = results.filter(r => r.pass).length;
  if (count) count.textContent = `${passed}/${results.length} geçti`;

  tbody.innerHTML = results.map(r => {
    const statusIcon = r.pass ? `<span class="test-ok">&#10003; GECTI</span>` : `<span class="test-fail">&#10007; BASARISIZ</span>`;
    const errNote    = r.error ? `<br><span style="color:var(--accent-orange);font-size:10px">${r.error}</span>` : "";
    return `
      <tr class="${r.pass ? "" : "row-attack"}">
        <td>${statusIcon}</td>
        <td>${attackPill(r.type)}</td>
        <td style="color:var(--text-secondary)">${r.label}${errNote}</td>
        <td>${expectedPill(r.expected)}</td>
        <td>${boolPill(r.detected, r.expected)}</td>
        <td>${confBadge(r.confidence)}</td>
      </tr>`;
  }).join("");
}

function updateTestSummary(summary, running) {
  const el = document.getElementById("test-summary-text");
  if (!el) return;
  if (running) { el.textContent = "Testler çalışıyor..."; return; }
  if (!summary) return;
  const all = summary.total;
  const ok  = summary.passed;
  const fail= summary.failed;
  el.innerHTML = `Toplam: <strong>${all}</strong> &nbsp;|&nbsp; `
    + `<span style="color:var(--accent-green)">Geçti: ${ok}</span> &nbsp;|&nbsp; `
    + `<span style="color:var(--accent-red)">Başarısız: ${fail}</span>`;
}

// ═══════════════════════════════════════════
// OFFLİNE TEST — MODEL DOĞRULAMA
// ═══════════════════════════════════════════

async function runOfflineTest(type, templateKey = null) {
  const tbody   = document.getElementById("offline-results-body");
  const summary = document.getElementById("offline-summary-text");
  const countEl = document.getElementById("offline-result-count");

  if (tbody)   tbody.innerHTML = `<tr><td colspan="6" style="padding:24px;text-align:center;color:#94a3b8;font-size:12px">Çalışıyor...</td></tr>`;
  if (summary) summary.textContent = "Testler çalışıyor...";
  if (countEl) countEl.textContent = "—";

  try {
    const res  = await fetch("/api/test/offline", {
      method:  "POST",
      headers: { "Content-Type": "application/json" },
      body:    JSON.stringify({ type, template: templateKey }),
    });
    const data = await res.json();
    _renderOfflineResults(data.results || []);
    _updateOfflineSummary(data.summary);
  } catch (err) {
    if (tbody)   tbody.innerHTML = `<tr><td colspan="6" style="padding:24px;text-align:center;color:#f87171;font-size:12px">Hata: ${err.message}</td></tr>`;
    if (summary) summary.textContent = "Bağlantı hatası.";
  }
}

function _renderOfflineResults(results) {
  const tbody   = document.getElementById("offline-results-body");
  const countEl = document.getElementById("offline-result-count");
  if (!tbody) return;

  if (!results.length) {
    tbody.innerHTML = `<tr><td colspan="6" style="padding:24px;text-align:center;color:#64748b;font-size:12px">Sonuç bulunamadı.</td></tr>`;
    return;
  }

  const passed = results.filter(r => r.pass).length;
  if (countEl) countEl.textContent = `${passed}/${results.length} geçti`;

  const TYPE_LABELS = { dos: "DoS", brute_force: "Brute Force", sql_injection: "SQL Injection" };
  const TYPE_COLORS = { dos: "#f87171", brute_force: "#fb923c", sql_injection: "#c084fc" };

  tbody.innerHTML = results.map(r => {
    const statusEl = r.pass
      ? `<span style="color:#4ade80;font-weight:700;font-size:11px">&#10003; GEÇTİ</span>`
      : `<span style="color:#f87171;font-weight:700;font-size:11px">&#10007; KALDI</span>`;

    const typeColor = TYPE_COLORS[r.type] || "#94a3b8";
    const typeLabel = TYPE_LABELS[r.type]  || r.type;

    const expectedEl = r.expected
      ? `<span style="padding:2px 8px;border-radius:4px;background:rgba(127,29,29,0.4);color:#fca5a5;font-size:10px">Saldırı</span>`
      : `<span style="padding:2px 8px;border-radius:4px;background:rgba(30,41,59,0.8);color:#94a3b8;font-size:10px">Temiz</span>`;

    const detectedEl = r.detected === true
      ? `<span style="padding:2px 8px;border-radius:4px;background:rgba(127,29,29,0.4);color:#fca5a5;font-size:10px">Saldırı</span>`
      : r.detected === false
      ? `<span style="padding:2px 8px;border-radius:4px;background:rgba(30,41,59,0.8);color:#94a3b8;font-size:10px">Temiz</span>`
      : `<span style="padding:2px 8px;border-radius:4px;background:rgba(120,53,15,0.4);color:#fcd34d;font-size:10px">Hata</span>`;

    const conf     = Math.round((r.confidence || 0) * 100);
    const barColor = r.detected ? "#ef4444" : "#3b82f6";
    const confEl   = `<div style="display:flex;align-items:center;gap:8px;min-width:110px">
      <div style="flex:1;background:#1e293b;border-radius:99px;height:5px;overflow:hidden">
        <div style="background:${barColor};height:5px;width:${conf}%;border-radius:99px"></div>
      </div>
      <span style="font-size:10px;color:#94a3b8;width:28px;text-align:right">%${conf}</span>
    </div>`;

    const rowBg  = r.pass ? "" : "background:rgba(127,29,29,0.08)";
    const errNote = r.error ? `<span style="display:block;font-size:10px;color:#fb923c;margin-top:2px">${r.error}</span>` : "";
    return `<tr style="border-bottom:1px solid rgba(51,65,85,0.5);${rowBg}">
      <td style="padding:8px 16px">${statusEl}</td>
      <td style="padding:8px 16px;color:${typeColor};font-weight:600;font-size:11px">${typeLabel}</td>
      <td style="padding:8px 16px;color:#cbd5e1;font-size:11px">${r.label || ""}${errNote}</td>
      <td style="padding:8px 16px">${expectedEl}</td>
      <td style="padding:8px 16px">${detectedEl}</td>
      <td style="padding:8px 16px">${confEl}</td>
    </tr>`;
  }).join("");
}

function _updateOfflineSummary(summary) {
  const el = document.getElementById("offline-summary-text");
  if (!el || !summary) return;
  el.innerHTML = `Toplam: <strong style="color:#e2e8f0">${summary.total}</strong> &nbsp;|&nbsp; `
    + `<span style="color:#4ade80">Geçti: ${summary.passed}</span> &nbsp;|&nbsp; `
    + `<span style="color:#f87171">Kaldı: ${summary.failed}</span>`;
}


// ═══════════════════════════════════════════
// CANLI SALDIRI — BAŞLATMA
// ═══════════════════════════════════════════

async function startLiveAttack(type) {
  const body = { type };

  if (type === "dos") {
    const dur  = parseInt(document.getElementById("live-dos-duration")?.value  || 10);
    const thr  = parseInt(document.getElementById("live-dos-threads")?.value   || 20);
    body.count       = dur * thr * 2;
    body.concurrency = thr;
    body.delay_ms    = 50;
  } else if (type === "bruteforce") {
    body.usernames = document.getElementById("live-bf-users")?.value     || "admin\nroot";
    body.passwords = document.getElementById("live-bf-passwords")?.value || "password\n123456";
  } else if (type === "highvolumebrute") {
    body.count       = parseInt(document.getElementById("live-hvbf-count")?.value   || 200);
    body.concurrency = parseInt(document.getElementById("live-hvbf-threads")?.value || 20);
    body.delay       = 0;
    body.usernames   = "admin\nroot\nuser\nadministrator\ntest\nguest";
    body.passwords   = "password\n123456\nadmin\nqwerty\nletmein\nadmin123";
  } else if (type === "sqli") {
    body.payloads = document.getElementById("live-sqli-payloads")?.value || "";
  }

  try {
    const res  = await fetch("/api/test/live", {
      method:  "POST",
      headers: { "Content-Type": "application/json" },
      body:    JSON.stringify(body),
    });
    const data = await res.json();
    if (res.ok) {
      const labels = { dos: "DoS", bruteforce: "Brute Force", sqli: "SQL Injection" };
      showToast(
        "Simülasyon Başlatıldı",
        `🚀 ${labels[type] || type} saldırı simülasyonu başlatıldı! Docker sunucunuza gerçek paketler gönderiliyor. Lütfen grafikler ve canlı alarmlar için 'Genel Bakış' sekmesine geçiniz.`,
        "success"
      );
    } else {
      showToast("Hata", data.error || "Bilinmeyen hata.", "error");
    }
  } catch (err) {
    showToast("Bağlantı Hatası", err.message, "error");
  }
}

// ═══════════════════════════════════════════
// TEST SAYFASI DURUM BARLARI
// ═══════════════════════════════════════════

async function initTestPage() {
  try {
    const res  = await fetch("/api/health");
    const data = await res.json();

    const dockerDot  = document.getElementById("docker-dot");
    const dockerText = document.getElementById("docker-status-text");
    if (data.container) {
      const ok = data.container.status === "connected";
      if (dockerDot)  dockerDot.style.background  = ok ? "#4ade80" : "#ef4444";
      if (dockerText) dockerText.textContent = ok
        ? `${data.container.name} [BAĞLI]`
        : `${data.container.name} [HATA — ${data.container.status}]`;
    }

    const modelsDot  = document.getElementById("models-dot");
    const modelsText = document.getElementById("models-status-text");
    if (data.models) {
      const ok = data.models.loaded >= data.models.total;
      if (modelsDot)  modelsDot.style.background  = ok ? "#4ade80" : "#facc15";
      if (modelsText) modelsText.textContent = `${data.models.loaded}/${data.models.total} Motor Yüklendi [${ok ? "HAZIR" : "EKSİK"}]`;
    }
  } catch (_) {
    // Sessizce geç — bağlantı hatası sidebar'da zaten gösterilir
  }
}

// ═══════════════════════════════════════════
// LOG SEÇİM SİSTEMİ
// ═══════════════════════════════════════════
const _selectedLogs = [];

function logToggleSelect(div) {
  const idx = _selectedLogs.findIndex(e => e._el === div);
  if (idx === -1) {
    div.classList.add("selected");
    _selectedLogs.push({ _el: div, ...JSON.parse(div.dataset.entry || "{}") });
  } else {
    div.classList.remove("selected");
    _selectedLogs.splice(idx, 1);
  }
  logSelectionUpdatePanel();
}

function logSelectionClear() {
  _selectedLogs.forEach(e => e._el?.classList.remove("selected"));
  _selectedLogs.length = 0;
  logSelectionUpdatePanel();
}

function logSelectionUpdatePanel() {
  const panel   = document.getElementById("selected-logs-panel");
  const badge   = document.getElementById("selected-count-badge");
  const compact = document.getElementById("selected-logs-compact");
  const full    = document.getElementById("selected-logs-full");
  if (!panel) return;

  if (_selectedLogs.length === 0) {
    panel.style.display = "none";
    return;
  }

  panel.style.display = "block";
  badge.textContent = `${_selectedLogs.length} satır`;

  const lines = _selectedLogs.map(e =>
    `${e.time}  ${e.ip}  ${e.method}  ${e.status}  ${e.path}${e.detector ? "  ["+e.detector+"]" : ""}`
  );
  compact.textContent = lines.slice(0, 3).join("\n") + (_selectedLogs.length > 3 ? `\n+${_selectedLogs.length - 3} daha...` : "");
  full.textContent    = lines.join("\n");
}

function toggleSelectedLogsExpand() {
  const compact = document.getElementById("selected-logs-compact");
  const full    = document.getElementById("selected-logs-full");
  const hint    = document.getElementById("selected-logs-expand-hint");
  if (!full) return;
  const expanded = full.style.display !== "none";
  full.style.display    = expanded ? "none"  : "block";
  compact.style.display = expanded ? ""      : "none";
  hint.textContent      = expanded ? "▼ tümünü gör" : "▲ gizle";
}

async function aiAnalyzeSelectedLogs() {
  if (_selectedLogs.length === 0) return;
  navigate("ai");

  const lines = _selectedLogs.map(e =>
    `[${e.time}] ${e.ip} ${e.method} ${e.status} ${e.path}${e.detector ? " → " + e.detector : ""}`
  ).join("\n");

  const msg = `Aşağıdaki ${_selectedLogs.length} log satırını analiz et. Saldırı içerip içermediğini, pattern'ini ve önerilen aksiyonları Türkçe açıkla:\n\n${lines}`;
  aiAppendMessage("user", `${_selectedLogs.length} log satırı analiz isteği gönderildi`);
  const thinking = aiAppendMessage("thinking", "Loglar analiz ediliyor...");

  try {
    const resp = await fetch("/api/ai/chat", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ message: msg })
    });
    const data = await resp.json();
    thinking.remove();
    aiAppendMessage("bot", data.response || data.error || "Yanıt alınamadı.");
  } catch (e) {
    thinking.remove();
    aiAppendMessage("bot", "Bağlantı hatası: " + e.message);
  }
}

// ═══════════════════════════════════════════
// AI ASISTAN
// ═══════════════════════════════════════════

function aiAppendMessage(role, text) {
  const container = document.getElementById("ai-chat-messages");
  if (!container) return null;
  const div = document.createElement("div");
  div.className = role === "user"
    ? "ai-msg ai-msg--user"
    : role === "thinking"
    ? "ai-msg ai-msg--thinking"
    : "ai-msg ai-msg--bot";
  div.textContent = text;
  container.appendChild(div);
  container.scrollTop = container.scrollHeight;
  return div;
}

async function aiSendChat() {
  const input = document.getElementById("ai-chat-input");
  const btn   = document.getElementById("ai-send-btn");
  const msg   = input?.value.trim();
  if (!msg) return;

  input.value = "";
  input.disabled = true;
  btn.disabled = true;
  btn.textContent = "...";

  aiAppendMessage("user", msg);
  const thinking = aiAppendMessage("thinking", "Yanıt üretiliyor...");

  try {
    const resp = await fetch("/api/ai/chat", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ message: msg })
    });
    const data = await resp.json();
    thinking.remove();
    aiAppendMessage("bot", data.response || data.error || "Yanıt alınamadı.");
  } catch (e) {
    thinking.remove();
    aiAppendMessage("bot", "Bağlantı hatası: " + e.message);
  } finally {
    input.disabled = false;
    btn.disabled = false;
    btn.textContent = "Gönder";
    input.focus();
  }
}

async function aiRequestSummary() {
  const btn = document.getElementById("ai-summary-btn");
  if (!btn) return;
  btn.disabled = true;
  btn.textContent = "⏳ Üretiliyor...";

  const thinking = aiAppendMessage("thinking", "Son 1 saatin verileri analiz ediliyor...");
  try {
    const resp = await fetch("/api/ai/summary", { method: "POST" });
    const data = await resp.json();
    thinking.remove();
    aiAppendMessage("bot", "📊 Son 1 Saat Özeti:\n\n" + (data.summary || data.error || "Yanıt alınamadı."));
  } catch (e) {
    thinking.remove();
    aiAppendMessage("bot", "Bağlantı hatası: " + e.message);
  } finally {
    btn.disabled = false;
    btn.textContent = "📊 Son 1 Saat Özeti";
  }
}

async function aiSendQuery(msg) {
  aiAppendMessage("user", msg);
  const thinking = aiAppendMessage("thinking", "Yanıt üretiliyor...");
  try {
    const resp = await fetch("/api/ai/chat", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ message: msg })
    });
    const data = await resp.json();
    thinking.remove();
    aiAppendMessage("bot", data.response || data.error || "Yanıt alınamadı.");
  } catch (e) {
    thinking.remove();
    aiAppendMessage("bot", "Bağlantı hatası: " + e.message);
  }
}

async function aiLoadIpRisks() {
  const list = document.getElementById("ip-risk-list");
  if (!list) return;
  list.innerHTML = '<span style="color:var(--text-muted)">Yükleniyor...</span>';

  try {
    const resp = await fetch("/api/ai/ip-risk");
    const data = await resp.json();
    const risks = data.ip_risks || [];

    if (!risks.length) {
      list.innerHTML = '<span style="color:var(--text-muted)">Henüz saldırı verisi yok.</span>';
      return;
    }

    list.innerHTML = risks.map(r => `
      <div class="risk-row">
        <span style="font-family:var(--font-mono);color:var(--accent-cyan);font-size:0.78rem;flex:1">${r.ip}</span>
        <span class="risk-badge risk-${r.level.toLowerCase()}">${r.level}</span>
        ${r.coordinated ? '<span class="coord-badge">Koordineli</span>' : ''}
        <span style="color:var(--text-muted);font-size:0.75rem">${r.count} hit</span>
      </div>
    `).join("");
  } catch (e) {
    list.innerHTML = `<span style="color:var(--text-muted)">Hata: ${e.message}</span>`;
  }
}

// ═══════════════════════════════════════════
// INITIAL LOAD
// ═══════════════════════════════════════════
fetchStats();
navigate("overview");
initTestPage();
