#!/bin/bash
# Launch VENOM Web UI
if [ "$EUID" -ne 0 ]; then
    echo "[!] Must run as root"
    exit 1
fi
cd "$(dirname "$0")"
python3 -m flask --app app run --host=0.0.0.0 --port=8080
