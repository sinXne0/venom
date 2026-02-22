/* VENOM Web UI - Frontend Logic */

"use strict";

// ── State ─────────────────────────────────────────────────
let selectedNetwork = null;

// ── SSE terminal stream ────────────────────────────────────
const terminal = document.getElementById("terminal");
const evtSource = new EventSource("/stream");

evtSource.onmessage = (e) => {
  if (!e.data) return;           // keepalive
  const line = JSON.parse(e.data);
  appendTerminal(line);
};

evtSource.onerror = () => {
  appendTerminal("[!] Stream disconnected.\n", "warn");
};

function appendTerminal(text, forceCls = null) {
  if (!text) return;
  const div = document.createElement("div");
  if (forceCls) {
    div.className = "line-" + forceCls;
  } else if (/\[\+\]|OK|captured|success/i.test(text)) {
    div.className = "line-ok";
  } else if (/\[!\]|error|fail|warn/i.test(text)) {
    div.className = "line-warn";
  } else if (/\[\*\]|starting|monitor|scan/i.test(text)) {
    div.className = "line-info";
  } else if (/username|password|mschapv2|credential/i.test(text)) {
    div.className = "line-cred";
  }
  div.textContent = text;
  terminal.appendChild(div);
  terminal.scrollTop = terminal.scrollHeight;
}

function clearTerminal() {
  terminal.innerHTML = "";
}

// ── API helpers ────────────────────────────────────────────
async function api(path, body = null) {
  const opts = body
    ? { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) }
    : { method: "GET" };
  try {
    const r = await fetch(path, opts);
    return await r.json();
  } catch (err) {
    appendTerminal(`[!] API error: ${err}\n`, "warn");
    return null;
  }
}

async function refreshState() {
  const s = await api("/api/state");
  if (!s) return;
  document.getElementById("st-iface").textContent = s.wifi_iface || "Not Set";
  document.getElementById("st-mon").textContent   = s.monitor_iface || "No";
  document.getElementById("st-ssid").textContent  = s.target_ssid || "Not Set";
  document.getElementById("st-bssid").textContent = s.target_bssid || "—";
  document.getElementById("st-chan").textContent   = s.target_channel || "—";
}

// ── Interface ─────────────────────────────────────────────
async function setIface() {
  const sel = document.getElementById("iface-select");
  if (!sel.value) return;
  const r = await api("/api/set_iface", { iface: sel.value });
  if (r?.ok) {
    appendTerminal(`[*] Interface set: ${sel.value}\n`, "info");
    refreshState();
  }
}

async function refreshIfaces() {
  const ifaces = await api("/api/interfaces");
  if (!ifaces) return;
  const sel = document.getElementById("iface-select");
  const cur = sel.value;
  sel.innerHTML = '<option value="">-- select --</option>' +
    ifaces.map(i => `<option value="${i}" ${i === cur ? "selected" : ""}>${i}</option>`).join("");
  appendTerminal(`[*] Interfaces refreshed\n`, "info");
}

async function enableMonitor() {
  appendTerminal("[*] Enabling monitor mode...\n", "info");
  const r = await api("/api/monitor/enable", {});
  if (r?.ok) refreshState();
}

async function disableMonitor() {
  appendTerminal("[*] Disabling monitor mode...\n", "info");
  const r = await api("/api/monitor/disable", {});
  if (r?.ok) refreshState();
}

// ── Scan ──────────────────────────────────────────────────
async function scanNetworks() {
  const sel = document.getElementById("iface-select");
  appendTerminal("[*] Scanning networks...\n", "info");
  const nets = await api("/api/scan", { iface: sel.value });
  if (!nets) return;
  renderScanResults(nets);
}

function renderScanResults(nets) {
  const container = document.getElementById("scan-results");
  if (!nets.length) {
    container.innerHTML = '<div style="color:#555;font-size:11px">No networks found.</div>';
    return;
  }
  container.innerHTML = nets.map((n, i) => `
    <div class="scan-row" onclick="selectTarget(${i})" id="scan-row-${i}"
         data-bssid="${n.bssid}" data-ssid="${escHtml(n.ssid)}"
         data-channel="${n.channel}" data-signal="${n.signal}">
      <div class="scan-ssid">${escHtml(n.ssid) || "<hidden>"}</div>
      <div class="scan-meta">
        ${n.bssid} &nbsp;
        <span class="scan-signal">${n.signal || "?"}</span> &nbsp;
        CH ${n.channel || "?"} &nbsp;
        ${escHtml(n.vendor || "")}
      </div>
    </div>
  `).join("");
}

async function selectTarget(idx) {
  const row = document.getElementById(`scan-row-${idx}`);
  if (!row) return;
  document.querySelectorAll(".scan-row").forEach(r => r.classList.remove("selected"));
  row.classList.add("selected");
  const data = {
    bssid:   row.dataset.bssid,
    ssid:    row.dataset.ssid,
    channel: row.dataset.channel,
  };
  const r = await api("/api/set_target", data);
  if (r?.ok) {
    appendTerminal(`[+] Target: ${data.ssid} (${data.bssid}) CH ${data.channel}\n`, "ok");
    refreshState();
  }
}

async function channelHop() {
  appendTerminal("[*] Channel-hop scan is handled by the CLI (venom.sh → option 4).\n", "info");
  appendTerminal("[!] Switch to the terminal and run: sudo ./venom.sh\n", "warn");
}

// ── Attacks ───────────────────────────────────────────────
async function deauthAttack() {
  const packets = document.getElementById("deauth-packets").value || 64;
  const client  = document.getElementById("deauth-client").value.trim();
  appendTerminal(`[*] Deauth → packets=${packets} client=${client || "broadcast"}\n`, "info");
  await api("/api/attack/deauth", { packets: parseInt(packets), client });
}

async function captureHandshake() {
  appendTerminal("[*] Starting WPA handshake capture...\n", "info");
  await api("/api/attack/handshake", {});
}

async function pmkidAttack() {
  appendTerminal("[*] Starting PMKID attack (60s capture)...\n", "info");
  await api("/api/attack/pmkid", {});
}

async function evilTwin() {
  appendTerminal("[*] Launching Evil Twin AP...\n", "info");
  await api("/api/attack/evil_twin", {});
}

async function wpsAttack() {
  appendTerminal("[*] Starting WPS PIN attack...\n", "info");
  await api("/api/attack/wps", {});
}

async function triggerVenom() {
  appendTerminal("[*] ▶ LAUNCHING VENOM — WPA-Enterprise Rogue AP...\n", "info");
  await api("/api/attack/venom", {});
}

async function enumClients() {
  appendTerminal("[*] Enumerating clients...\n", "info");
  // Runs via the SSE stream from a background shell command
  await api("/api/attack/deauth", { packets: 0 }); // placeholder hint
  appendTerminal("[!] Client enumeration: use CLI venom.sh → option 5 for full interactive output\n", "warn");
}

async function stopProcess() {
  const r = await api("/api/stop", {});
  appendTerminal(`[*] ${r?.msg || "Stop sent"}\n`, "info");
}

// ── Config ────────────────────────────────────────────────
function saveConfig() {
  appendTerminal("[*] Save config is available in the CLI version (venom.sh → S)\n", "info");
}
function loadConfig() {
  appendTerminal("[*] Load config is available in the CLI version (venom.sh → L)\n", "info");
}

// ── Loot ─────────────────────────────────────────────────
async function refreshLoot() {
  const files = await api("/api/loot");
  if (!files) return;
  const list = document.getElementById("loot-list");
  if (!files.length) {
    list.innerHTML = '<div style="color:#444;font-size:11px">No loot yet.</div>';
    return;
  }
  list.innerHTML = files.map(f => `
    <div class="loot-item" onclick="viewLoot('${f.name}')">
      <span>${f.name}</span>
      <span class="loot-size">${fmtSize(f.size)}</span>
    </div>
  `).join("");
}

async function viewLoot(filename) {
  const viewer = document.getElementById("loot-viewer");
  const data = await api(`/api/loot/${encodeURIComponent(filename)}`);
  if (!data?.content) return;
  viewer.style.display = "block";
  viewer.textContent = data.content;
}

// ── Helpers ───────────────────────────────────────────────
function showSection(name) {
  document.getElementById(`section-${name}`)?.scrollIntoView({ behavior: "smooth" });
}

function escHtml(str) {
  if (!str) return "";
  return str.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;");
}

function fmtSize(bytes) {
  if (bytes < 1024) return bytes + "B";
  if (bytes < 1048576) return (bytes / 1024).toFixed(1) + "K";
  return (bytes / 1048576).toFixed(1) + "M";
}

// ── Init ─────────────────────────────────────────────────
refreshState();
refreshLoot();
appendTerminal("[+] VENOM Web UI ready. Select interface and target to begin.\n", "ok");
