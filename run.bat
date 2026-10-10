@echo off
cd /d "%~dp0backend"
python -m pip install -r requirements.txt
set DEV_MODE=1
echo.
echo Myphema backend: http://localhost:5000   (DEV_MODE on: OTP codes are shown on screen)
python app.py
