@echo off
cd /d "%~dp0"
echo Starting WireLens LIVE (real host sockets)...
where py >nul 2>&1 && set PY=py -3
if not defined PY where python >nul 2>&1 && set PY=python
if not defined PY (
  echo Python 3.10+ is required.
  pause
  exit /b 1
)
if not exist .venv (
  %PY% -m venv .venv
  call .venv\Scripts\activate.bat
  pip install -r requirements.txt
) else (
  call .venv\Scripts\activate.bat
)
echo Keep this window open. Open http://127.0.0.1:8787/
python -m wirelens
if errorlevel 1 pause
