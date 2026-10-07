@echo off
REM Starts the JLPL portal on Windows. Edit the values below, then run this file.
REM For a permanent Windows service, see "Run as a service" in README.md.
set PORT=8080
set HOST=127.0.0.1
set AUTH_MODE=local
set DATA_DIR=%~dp0data
cd /d %~dp0
node server.js
pause
