#!/usr/bin/env bash
cd "$(dirname "$0")/backend" || exit 1
python3 -m pip install -r requirements.txt
export DEV_MODE=1
echo "Myphema backend: http://localhost:5000   (DEV_MODE on: OTP codes are shown on screen)"
python3 app.py
