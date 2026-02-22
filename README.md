# VENOM - Wireless Pentesting Toolkit

```
 __   _____ _  _  ___  __  __
 \ \ / / __| \| |/ _ \|  \/  |
  \ V /| _|| .` | (_) | |\/| |
   \_/ |___|_|\_|\___/|_|  |_|
       Wireless Pentesting Toolkit v3.0
```

> ⚠️ **AUTHORIZED SECURITY TESTING ONLY.** For use on networks you own or have explicit written permission to test. Unauthorized use is illegal.

---

## Features

### CLI (`venom.sh`)
| # | Feature |
|---|---------|
| 1 | Select wireless interface |
| 2 | Scan & select target (SSID, BSSID, channel, signal, vendor) |
| 3 | Toggle monitor mode |
| 4 | Channel-hopping scan (airodump-ng CSV output) |
| 5 | Enumerate associated clients |
| 6 | Deauthentication attack (broadcast or targeted) |
| 7 | WPA handshake capture (auto-deauth to force reconnect) |
| 8 | PMKID attack (hcxdumptool + hashcat output) |
| 9 | Evil Twin AP (rogue open AP + background deauth) |
| A | WPS PIN attack (reaver / bully) |
| V | **VENOM Attack** — WPA-Enterprise rogue AP, cert generation, live credential feed |
| W | **Launch Web UI** — starts the Flask web UI in the background |
| S/L | Save / load config |

### Web UI (`webui/`)
- Real-time terminal output via Server-Sent Events (SSE)
- Full attack controls in browser
- Network scan with vendor lookup
- Loot file browser
- Retro "LAUNCHING VIRUS" theme

---

## Requirements

Debian/Ubuntu (Kali recommended). Run as root.

```bash
sudo apt-get install hostapd aircrack-ng tcpdump openssl iw python3-flask
```

Optional (for PMKID attack):
```bash
sudo apt-get install hcxdumptool hcxtools
```

Optional (for WPS attack):
```bash
sudo apt-get install reaver
```

Optional (for full WPA-Enterprise credential logging):
```bash
sudo apt-get install hostapd-wpe
```

---

## Usage

### CLI
```bash
git clone https://github.com/sinXne0/venom.git
cd venom
chmod +x venom.sh
sudo ./venom.sh
```

Flags:
```
-i <iface>   Set interface at launch
-l <dir>     Set loot output directory
-c <file>    Load a saved config
-h           Help
```

### Web UI
Launch from the CLI menu (`W`), or directly:
```bash
sudo bash webui/start.sh
# Open http://localhost:8080
```

---

## Loot

All output is saved to `./venom_loot/` by default:
- `venom_YYYYMMDD.log` — session log
- `hs_<ssid>_<ts>-01.cap` — WPA handshake captures
- `pmkid_<ssid>_<ts>.hash` — PMKID hashes
- `wps_<ts>.log` — WPS attack output
- `venom_creds_<ts>.log` — WPA-Enterprise harvested credentials
- `webui.log` — Web UI server log

---

## Disclaimer

This tool is for authorized penetration testing and educational use only. The developer is not responsible for any misuse.
