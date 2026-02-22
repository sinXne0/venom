/* ============================================================
   VENOM v3.0 — Web UI Frontend
   ============================================================ */

"use strict";

// ── State ──────────────────────────────────────────────────────
const startTime = Date.now();
let isRunning   = false;

// ── DOM refs ───────────────────────────────────────────────────
const terminal      = document.getElementById("terminal");
const procIndicator = document.getElementById("proc-indicator");
const badgeStatus   = document.getElementById("badge-status");
const lbDots        = document.getElementById("lb-dots");

// ── Uptime clock ───────────────────────────────────────────────
function padZ(n) { return String(n).padStart(2, "0"); }
setInterval(() => {
  const s = Math.floor((Date.now() - startTime) / 1000);
  const h = Math.floor(s / 3600);
  const m = Math.floor((s % 3600) / 60);
  const sec = s % 60;
  const el = document.getElementById("uptime");
  if (el) el.textContent = `${padZ(h)}:${padZ(m)}:${padZ(sec)}`;
}, 1000);

// ── Launching bar animation ────────────────────────────────────
let dotCount = 0;
setInterval(() => {
  dotCount = (dotCount + 1) % 4;
  if (lbDots) lbDots.textContent = ".".repeat(dotCount);
}, 500);

// ── Process status ─────────────────────────────────────────────
function setRunning(active) {
  isRunning = active;
  if (procIndicator) procIndicator.classList.toggle("active", active);
  if (badgeStatus) {
    badgeStatus.textContent = active ? "RUNNING" : "IDLE";
    badgeStatus.classList.toggle("active", active);
  }
}

// ── SSE terminal stream ────────────────────────────────────────
const evtSource = new EventSource("/stream");
evtSource.onmessage = (e) => {
  if (!e.data || e.data.trim() === "") return;
  try {
    const line = JSON.parse(e.data);
    if (line) {
      appendTerminal(line);
      if (/exited with code/i.test(line)) setRunning(false);
      else setRunning(true);
    }
  } catch (_) {}
};
evtSource.onerror = () => appendTerminal("[!] Stream disconnected.\n", "warn");

// ── Terminal output ────────────────────────────────────────────
function appendTerminal(text, forceCls = null) {
  if (!text) return;
  const div = document.createElement("div");
  let cls = forceCls;
  if (!cls) {
    if (/\[\+\]|captured|success|\[OK\]/i.test(text))                    cls = "ok";
    else if (/\[!\]|error|fail|denied|invalid/i.test(text))              cls = "warn";
    else if (/\[\*\]|starting|monitor|scanning|launching/i.test(text))   cls = "info";
    else if (/username|password|mschapv2|credential|hash/i.test(text))   cls = "cred";
  }
  if (cls) div.className = "line-" + cls;
  div.textContent = text;
  terminal.appendChild(div);
  terminal.scrollTop = terminal.scrollHeight;
}

function clearTerminal() {
  terminal.innerHTML = "";
  appendTerminal("[*] Terminal cleared.\n", "info");
}

// ── API helper ─────────────────────────────────────────────────
async function api(path, body = null) {
  const opts = body !== null
    ? { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) }
    : { method: "GET" };
  try {
    const r = await fetch(path, opts);
    const data = await r.json();
    if (!r.ok) {
      appendTerminal(`[!] ${data.error || "Request failed"}\n`, "warn");
      return null;
    }
    return data;
  } catch (err) {
    appendTerminal(`[!] API error: ${err}\n`, "warn");
    return null;
  }
}

async function refreshState() {
  const s = await api("/api/state");
  if (!s) return;
  setText("st-iface", s.wifi_iface  || "NOT SET");
  setText("st-mon",   s.monitor_iface || "OFF");
  setText("st-ssid",  s.target_ssid  || "NOT SET");
  setText("st-bssid", s.target_bssid || "—");
  setText("st-chan",   s.target_channel || "—");
}

function setText(id, val) {
  const el = document.getElementById(id);
  if (el) el.textContent = val;
}

// ── Interface ──────────────────────────────────────────────────
async function setIface() {
  const sel = document.getElementById("iface-select");
  if (!sel.value) { appendTerminal("[!] No interface selected.\n", "warn"); return; }
  const r = await api("/api/set_iface", { iface: sel.value });
  if (r?.ok) { appendTerminal(`[+] Interface set: ${sel.value}\n`, "ok"); refreshState(); }
}

async function refreshIfaces() {
  const ifaces = await api("/api/interfaces");
  if (!ifaces) return;
  const sel = document.getElementById("iface-select");
  const cur = sel.value;
  sel.innerHTML = '<option value="">— select interface —</option>' +
    ifaces.map(i => `<option value="${esc(i)}"${i === cur ? " selected" : ""}>${esc(i)}</option>`).join("");
  appendTerminal(`[*] Found ${ifaces.length} interface(s).\n`, "info");
}

async function enableMonitor() {
  appendTerminal("[*] Enabling monitor mode...\n", "info");
  setRunning(true);
  const r = await api("/api/monitor/enable", {});
  if (r?.ok) { appendTerminal(`[+] Monitor: ${r.state.monitor_iface || "enabled"}\n`, "ok"); refreshState(); }
}

async function disableMonitor() {
  appendTerminal("[*] Disabling monitor mode...\n", "info");
  const r = await api("/api/monitor/disable", {});
  if (r?.ok) { appendTerminal("[+] Monitor mode disabled.\n", "ok"); refreshState(); }
}

// ── Scan ───────────────────────────────────────────────────────
async function scanNetworks() {
  const sel = document.getElementById("iface-select");
  const btn = document.getElementById("scan-btn-text");
  if (btn) btn.textContent = "⏳ SCANNING...";
  appendTerminal("[*] Scanning for networks...\n", "info");
  const nets = await api("/api/scan", { iface: sel.value });
  if (btn) btn.textContent = "▶ SCAN NETWORKS";
  if (!nets) return;
  renderScan(nets);
  appendTerminal(`[+] Found ${nets.length} network(s).\n`, "ok");
}

function signalBars(sig) {
  const dbm = parseFloat(sig) || -100;
  // -50+ = 4 bars, -60 = 3, -70 = 2, -80 = 1, worse = 0
  const bars = dbm >= -50 ? 4 : dbm >= -65 ? 3 : dbm >= -75 ? 2 : dbm >= -85 ? 1 : 0;
  const heights = [4, 6, 8, 10];
  return `<span class="sig-bar">` +
    heights.map((h, i) =>
      `<span style="height:${h}px" ${i < bars ? 'class="lit"' : ""}></span>`
    ).join("") + `</span>`;
}

function renderScan(nets) {
  const c = document.getElementById("scan-results");
  if (!nets.length) {
    c.innerHTML = '<div class="scan-empty">No networks found.</div>';
    return;
  }
  c.innerHTML = nets.map((n, i) => `
    <div class="scan-row" id="sr-${i}" onclick="selectTarget(${i})"
         data-bssid="${esc(n.bssid)}" data-ssid="${esc(n.ssid)}"
         data-channel="${esc(n.channel)}" data-signal="${esc(n.signal)}">
      <div class="scan-ssid">${esc(n.ssid) || "<hidden>"}</div>
      <div class="scan-bssid">${esc(n.bssid)}</div>
      <div class="scan-meta">
        <span class="scan-ch">CH ${esc(n.channel) || "?"}</span>
        <span class="scan-sig">${esc(n.signal) || "?"}${signalBars(n.signal)}</span>
        <span class="scan-vendor">${esc(n.vendor) || ""}</span>
      </div>
    </div>`
  ).join("");
}

async function selectTarget(idx) {
  const row = document.getElementById(`sr-${idx}`);
  if (!row) return;
  document.querySelectorAll(".scan-row").forEach(r => r.classList.remove("selected"));
  row.classList.add("selected");
  const data = { bssid: row.dataset.bssid, ssid: row.dataset.ssid, channel: row.dataset.channel };
  const r = await api("/api/set_target", data);
  if (r?.ok) {
    appendTerminal(`[+] Target locked: ${data.ssid} (${data.bssid}) CH ${data.channel}\n`, "ok");
    refreshState();
  }
}

function channelHop() {
  appendTerminal("[*] Channel-hop scan requires the CLI (venom.sh → option 4).\n", "info");
  appendTerminal("[!] Run: sudo ./venom.sh  then press 4\n", "warn");
}

// ── Attacks ────────────────────────────────────────────────────
async function deauthAttack() {
  const packets = document.getElementById("deauth-packets").value || 64;
  const client  = document.getElementById("deauth-client").value.trim();
  appendTerminal(`[*] Deauth → target=${getState("st-bssid")} packets=${packets} client=${client || "broadcast"}\n`, "info");
  setRunning(true);
  await api("/api/attack/deauth", { packets: parseInt(packets), client });
}

async function captureHandshake() {
  appendTerminal(`[*] Handshake capture → ${getState("st-ssid")} (${getState("st-bssid")})\n`, "info");
  setRunning(true);
  await api("/api/attack/handshake", {});
}

async function pmkidAttack() {
  appendTerminal(`[*] PMKID attack → ${getState("st-bssid")}\n`, "info");
  setRunning(true);
  await api("/api/attack/pmkid", {});
}

async function evilTwin() {
  appendTerminal(`[*] Evil Twin → cloning "${getState("st-ssid")}"\n`, "info");
  setRunning(true);
  await api("/api/attack/evil_twin", {});
}

async function wpsAttack() {
  appendTerminal(`[*] WPS PIN attack → ${getState("st-bssid")}\n`, "info");
  setRunning(true);
  await api("/api/attack/wps", {});
}

async function triggerVenom() {
  appendTerminal(`[*] ☠ LAUNCHING VENOM — Rogue WPA-Enterprise AP for "${getState("st-ssid")}"\n`, "info");
  setRunning(true);
  await api("/api/attack/venom", {});
}

async function enumClients() {
  appendTerminal("[*] Client enumeration runs via CLI (venom.sh → option 5).\n", "info");
  appendTerminal("[!] Run: sudo ./venom.sh  then press 5\n", "warn");
}

async function stopProcess() {
  const r = await api("/api/stop", {});
  appendTerminal(`[*] ${r?.msg || "Stop sent"}\n`, "info");
  setRunning(false);
}

// ── Config ─────────────────────────────────────────────────────
function saveConfig() {
  appendTerminal("[*] Config save is in the CLI (venom.sh → S).\n", "info");
}
function loadConfig() {
  appendTerminal("[*] Config load is in the CLI (venom.sh → L).\n", "info");
}

// ── Loot ───────────────────────────────────────────────────────
async function refreshLoot() {
  const files = await api("/api/loot");
  if (!files) return;
  const list = document.getElementById("loot-list");
  if (!files.length) {
    list.innerHTML = '<div class="scan-empty">No loot captured yet.</div>';
    return;
  }
  list.innerHTML = files.map(f => `
    <div class="loot-item" onclick="viewLoot('${esc(f.name)}')">
      <span class="loot-fname">${esc(f.name)}</span>
      <span class="loot-size">${fmtSize(f.size)}</span>
    </div>`
  ).join("");
}

async function viewLoot(filename) {
  const viewer = document.getElementById("loot-viewer");
  const data = await api(`/api/loot/${encodeURIComponent(filename)}`);
  if (!data?.content) return;
  viewer.style.display = "block";
  viewer.textContent = data.content;
}

// ── Scroll to section ──────────────────────────────────────────
function showSection(name) {
  const el = document.getElementById(`section-${name}`);
  if (el) el.scrollIntoView({ behavior: "smooth", block: "start" });
}

// ── Helpers ────────────────────────────────────────────────────
function esc(str) {
  if (!str) return "";
  return String(str)
    .replace(/&/g, "&amp;").replace(/</g, "&lt;")
    .replace(/>/g, "&gt;").replace(/"/g, "&quot;");
}

function getState(id) {
  return document.getElementById(id)?.textContent?.trim() || "?";
}

function fmtSize(bytes) {
  if (bytes < 1024) return bytes + " B";
  if (bytes < 1048576) return (bytes / 1024).toFixed(1) + " KB";
  return (bytes / 1048576).toFixed(1) + " MB";
}

// ── Init ───────────────────────────────────────────────────────
refreshState();
refreshLoot();
