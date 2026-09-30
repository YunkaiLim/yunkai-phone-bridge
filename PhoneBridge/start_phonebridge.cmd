@echo off
setlocal
title Yunkai Phone Bridge v0.7.2

echo ============================================================
echo  Yunkai Phone Bridge v0.7.2 - Android MCP
echo ============================================================
echo.
echo This server exposes only limited Android interaction tools.
echo It has NO delete, uninstall, clear-data, root, or arbitrary shell tool.
echo.

where adb >nul 2>nul
if errorlevel 1 (
  echo [ERROR] adb is not available in PATH.
  echo Install Android Platform Tools, add adb to PATH, then reopen this window.
  pause
  exit /b 1
)

echo Checking connected Android devices...
adb devices -l
echo.
echo Starting local MCP on http://127.0.0.1:8790/mcp
echo Keep this window open while using the Phone Bridge.
echo.
python server.py

echo.
echo Phone Bridge stopped.
pause
