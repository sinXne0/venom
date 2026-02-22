<div align="center">

```
 __   _____ _  _  ___  __  __
 \ \ / / __| \| |/ _ \|  \/  |
  \ V /| _|| .` | (_) | |\/| |
   \_/ |___|_|\_|\___/|_|  |_|
       Wireless Pentesting Toolkit
```

![Version](https://img.shields.io/badge/version-3.0-39ff14?style=flat-square&labelColor=0a0a0a)
![Platform](https://img.shields.io/badge/platform-Linux-39ff14?style=flat-square&labelColor=0a0a0a)
![Shell](https://img.shields.io/badge/shell-bash-39ff14?style=flat-square&labelColor=0a0a0a)
![Python](https://img.shields.io/badge/python-3.8+-39ff14?style=flat-square&labelColor=0a0a0a)
![License](https://img.shields.io/badge/license-MIT-39ff14?style=flat-square&labelColor=0a0a0a)

**A full-featured wireless security assessment toolkit with both a CLI and browser-based Web UI.**

> ⚠️ **AUTHORIZED SECURITY TESTING ONLY.**
> For use exclusively on networks you own or have **explicit written permission** to test.
> Unauthorized use is illegal under the Computer Fraud and Abuse Act and equivalent laws worldwide.

</div>

---

## Table of Contents

- [Features](#features)
- [Requirements](#requirements)
- [Installation](#installation)
- [CLI Usage](#cli-usage)
- [Web UI](#web-ui)
- [Attack Modules](#attack-modules)
- [Loot Structure](#loot-structure)
- [Troubleshooting](#troubleshooting)
- [Disclaimer](#disclaimer)

---

## Features

### CLI — `venom.sh`

```
┌─────────────────────────────────────────────────────────┐
│  1)  Select Wireless Interface                          │
│  2)  Scan & Select Target  (SSID / BSSID / CH / signal) │
│  3)  Toggle Monitor Mode                                │
│  4)  Channel-Hopping Scan  (airodump-ng CSV)            │
│  5)  Enumerate Associated Clients                       │
├─────────────────────────────────────────────────────────┤
│  6)  Deauthentication Attack  (broadcast or targeted)  │
│  7)  WPA Handshake Capture   (auto-deauth trigger)     │
│  8)  PMKID Attack            (no client needed)        │
│  9)  Evil Twin AP            (rogue AP + bg deauth)    │
│  A)  WPS PIN Attack          (reaver / bully)          │
│  V)  VENOM Attack            (WPA-Enterprise rogue AP) │
├─────────────────────────────────────────────────────────┤
│  W)  Launch Web UI           (Flask, port 8080)        │
│  S)  Save Config             (to venom.conf)           │
│  L)  Load Config                                        │
│  Q)  Quit                                               │
└─────────────────────────────────────────────────────────┘
```

### Web UI — `webui/`

- Real-time terminal output streamed via **Server-Sent Events (SSE)**
- Full attack controls — deauth, handshake, PMKID, evil twin, WPS, VENOM
- Network scanner with signal strength bars and vendor lookup
- Loot file browser with inline viewer
- Retro *LAUNCHING VIRUS* theme with CRT scanline overlay
- Responsive — works on tablet/phone too

---

## Requirements

**OS:** Kali Linux / Parrot OS / any Debian-based distro
**Privileges:** root required
**Hardware:** Wireless adapter capable of monitor mode + packet injection

### Required packages

```bash
sudo apt-get update
sudo apt-get install -y \
    aircrack-ng \
    hostapd \
    iw \
    tcpdump \
    openssl \
    python3-flask
```

### Optional packages (unlock additional modules)

| Package | Unlocks |
|---|---|
| `hcxdumptool` + `hcxtools` | PMKID attack |
| `reaver` | WPS PIN attack |
| `bully` | WPS PIN attack (fallback) |
| `hostapd-wpe` | Full WPA-Enterprise credential logging |
| `ieee-data` | Vendor lookup in scan results |

```bash
# Optional — install what you need
sudo apt-get install -y hcxdumptool hcxtools reaver ieee-data
```

---

## Installation

```bash
git clone https://github.com/sinXne0/venom.git
cd venom
chmod +x venom.sh webui/start.sh
```

---

## CLI Usage

```bash
sudo ./venom.sh
```

**Flags:**

| Flag | Description |
|------|-------------|
| `-i <iface>` | Pre-select wireless interface |
| `-l <dir>` | Set loot output directory (default: `./venom_loot`) |
| `-c <file>` | Load a saved config file |
| `-h` | Show help |

**Example — skip the interface selection step:**

```bash
sudo ./venom.sh -i wlan0
```

**Typical workflow:**

```
1. Run:  sudo ./venom.sh
2. [1]   Select your wireless interface (e.g. wlan0)
3. [2]   Scan and pick a target AP
4. [3]   Enable monitor mode (or it auto-enables per attack)
5. [6-V] Launch your chosen attack module
6. [Q]   Quit (disables monitor mode and stops Web UI automatically)
```

---

## Web UI

Launch from the CLI menu (`W`), or start it directly:

```bash
sudo bash webui/start.sh
```

Then open **http://localhost:8080** in your browser.

The Web UI runs in the background while the CLI stays fully functional. Quitting the CLI (`Q`) automatically stops the Web UI. All terminal output from attacks streams live to the browser.

**Architecture:**

```
Browser  ──SSE──▶  Flask (app.py)  ──subprocess──▶  System tools
                        │
                   /tmp/venom/*.sh   (temp scripts per attack)
                   ./venom_loot/     (all output saved here)
```

---

## Attack Modules

### Deauthentication Attack
Sends IEEE 802.11 deauthentication frames to disconnect clients from an AP. Can target all clients (broadcast) or a specific station MAC.

```
Requires: monitor mode, aireplay-ng
```

### WPA Handshake Capture
Starts airodump-ng on the target channel, sends deauth packets to force clients to reconnect, and captures the resulting 4-way WPA/WPA2 handshake for offline cracking.

```
Requires: monitor mode, airodump-ng, aireplay-ng
Crack:    aircrack-ng -w /usr/share/wordlists/rockyou.txt hs_*.cap
```

### PMKID Attack
Captures the PMKID from the AP's beacon/association frames using hcxdumptool. No connected client or deauth needed — works passively.

```
Requires: monitor mode, hcxdumptool, hcxtools
Crack:    hashcat -m 22000 pmkid_*.hash /usr/share/wordlists/rockyou.txt
```

### Evil Twin AP
Spawns a rogue open access point with the same SSID as the target. Simultaneously sends deauth frames to the real AP to push clients onto the fake one.

```
Requires: hostapd, aireplay-ng (for deauth)
```

### WPS PIN Attack
Brute-forces the 8-digit WPS PIN on WPS-enabled routers. Once found, the full WPA passphrase is recovered. Uses reaver (preferred) or bully as fallback.

```
Requires: monitor mode, reaver or bully
Note:     Can take hours — some APs have rate limiting or lockouts
```

### VENOM Attack — WPA-Enterprise Rogue AP
The namesake attack. Deploys a rogue WPA-Enterprise access point that mimics the target SSID. When clients attempt to authenticate, their EAP credentials (MSCHAPv2 hashes, plaintext via GTC/PAP, etc.) are captured and logged.

```
Requires: hostapd (or hostapd-wpe for full logging), openssl
Process:
  1. Generates a self-signed TLS certificate automatically
  2. Starts a rogue AP with EAP server (PEAP / TTLS / TLS / MD5)
  3. Deauths clients from the real AP in the background
  4. Streams captured credentials live to terminal / Web UI
  5. Saves all creds to venom_loot/venom_creds_<timestamp>.log

Crack MSCHAPv2:  hashcat -m 5500 <hash> /usr/share/wordlists/rockyou.txt
             or: asleap -C <challenge> -R <response> -W rockyou.txt
```

---

## Loot Structure

All output is saved to `./venom_loot/` by default.

```
venom_loot/
├── venom_YYYYMMDD.log          Session activity log (timestamped)
├── hs_<ssid>_<ts>-01.cap       WPA handshake pcap
├── pmkid_<ssid>_<ts>.pcapng    Raw PMKID capture
├── pmkid_<ssid>_<ts>.hash      Extracted PMKID hash (hashcat ready)
├── clients_<ts>-01.csv         Enumerated client stations
├── scan_<ts>-01.csv            Channel-hop scan results
├── wps_<ts>.log                WPS attack output / recovered PIN
├── venom_creds_<ts>.log        WPA-Enterprise harvested credentials
└── webui.log                   Web UI server log
```

Change the loot directory:

```bash
sudo ./venom.sh -l /tmp/engagement-output
```

---

## Troubleshooting

**Monitor mode fails**
```bash
# Kill conflicting processes manually
sudo airmon-ng check kill
sudo ip link set wlan0 down
sudo iw dev wlan0 set type monitor
sudo ip link set wlan0 up
```

**No networks found in scan**
```bash
# Make sure interface is up and not in monitor mode
sudo ip link set wlan0 up
iw dev wlan0 info   # should show "type managed"
```

**hostapd fails to start (Evil Twin / VENOM)**
```bash
# Check for conflicting AP or NetworkManager
sudo systemctl stop NetworkManager
sudo pkill hostapd
# Then retry the attack
```

**Flask Web UI won't start**
```bash
# Check if port 8080 is already in use
sudo lsof -i :8080
# Install Flask if missing
sudo apt-get install python3-flask
```

**hcxdumptool not found**
```bash
sudo apt-get install hcxdumptool hcxtools
```

**WPS attack rate-limited / locked out**

Some routers implement WPS lockout after a number of failed attempts. Wait 60 seconds and retry, or try the `-d` (delay) flag in reaver:
```bash
reaver -i wlan0mon -b <BSSID> -d 2 -vv
```

---

## Disclaimer

VENOM is developed for **authorized security testing, penetration testing engagements, and educational research only**.

- Do **not** use this tool against any network without **explicit written authorization**
- The developer assumes **no liability** for unauthorized or illegal use
- Always comply with your local laws and regulations

---

<div align="center">
Made by <a href="https://github.com/sinXne0">sinXne0</a>
</div>
