@echo off
setlocal EnableExtensions
cd /d "%~dp0"
title UniFlow - One-click launcher
set "PIP_DISABLE_PIP_VERSION_CHECK=1"

if not exist "app.py" (
  echo ERROR: app.py was not found.
  echo Put this BAT file in the same folder as app.py.
  pause
  exit /b 1
)
if not exist "requirements.txt" (
  echo ERROR: requirements.txt was not found.
  pause
  exit /b 1
)
if not exist "uniflow.db" (
  echo ERROR: uniflow.db was not found.
  echo Put the project database next to app.py before starting UniFlow.
  pause
  exit /b 1
)

where py >nul 2>&1
if errorlevel 1 (
  where python >nul 2>&1
  if errorlevel 1 (
    echo ERROR: Python was not found. Install Python 3.10 or newer.
    pause
    exit /b 1
  )
  set "PYTHON_CMD=python"
) else (
  set "PYTHON_CMD=py"
)

if not exist ".venv\Scripts\python.exe" (
  echo [1/3] Creating the Python environment in:
  echo %CD%\.venv
  %PYTHON_CMD% -m venv .venv
  if errorlevel 1 goto failed
) else (
  echo [1/3] Reusing the existing Python environment.
)

".venv\Scripts\python.exe" -c "import flask, cryptography, pywebpush, tzdata" >nul 2>&1
if errorlevel 1 (
  echo [2/3] Installing missing project dependencies. This is normally needed only once.
  ".venv\Scripts\python.exe" -m pip --disable-pip-version-check install -r requirements.txt
  if errorlevel 1 goto failed
) else (
  echo [2/3] All project dependencies are already installed.
)

echo [3/3] Starting UniFlow...
echo The browser will open at http://127.0.0.1:5000
echo Keep this window open while using UniFlow. Press Ctrl+C to stop it.
start "" cmd /c "timeout /t 2 /nobreak >nul & start http://127.0.0.1:5000"
".venv\Scripts\python.exe" app.py

echo.
echo UniFlow has stopped.
pause
exit /b 0

:failed
echo.
echo ERROR: UniFlow could not be prepared or started.
echo Check the messages above. An internet connection may be required for first-time dependency installation.
pause
exit /b 1
