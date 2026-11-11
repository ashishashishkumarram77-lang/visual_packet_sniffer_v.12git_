@echo off
title NetPulse Live Server & Tunnel Launcher
echo =====================================================================
echo   NetPulse: Starting Local Server + Live Public HTTPS Tunnel...
echo =====================================================================
start "NetPulse Python Server" cmd /k "python app.py"
timeout /t 3 /nobreak >nul
echo Starting Cloudflare Live Tunnel...
cloudflared tunnel --url http://localhost:5000
pause
