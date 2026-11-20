@echo off
rem AWS Tag Audit launcher for Windows.
rem   run.bat                -> opens the GUI
rem   run.bat scan ...       -> runs the CLI with those arguments (see README)
rem First run creates a private Python environment in .venv and installs boto3.
setlocal EnableExtensions
set "HERE=%~dp0"
set "VENV=%HERE%.venv"
set "PY=%VENV%\Scripts\python.exe"
set "PYTHONIOENCODING=utf-8"

if exist "%PY%" goto :deps

rem ---- find a Python 3.8+ to build the venv with ----
set "BASEPY="
where py >nul 2>nul && py -3 -c "import sys; sys.exit(sys.version_info < (3, 8))" >nul 2>nul && set "BASEPY=py -3"
if not defined BASEPY (
    where python >nul 2>nul && python -c "import sys; sys.exit(sys.version_info < (3, 8))" >nul 2>nul && set "BASEPY=python"
)
if not defined BASEPY (
    echo.
    echo Python 3.8 or newer was not found.
    echo Install it from https://www.python.org/downloads/ and tick "Add python.exe to PATH",
    echo then run this again.
    pause
    exit /b 1
)
echo Creating Python environment in .venv ...
rem --system-site-packages: reuse boto3 if it is already installed (helps on offline machines)
%BASEPY% -m venv --system-site-packages "%VENV%"
if errorlevel 1 (
    echo Could not create the virtual environment.
    pause
    exit /b 1
)

:deps
"%PY%" -c "import boto3" >nul 2>nul
if errorlevel 1 (
    echo Installing boto3 ...
    "%PY%" -m pip install --disable-pip-version-check -q -r "%HERE%requirements.txt"
    if errorlevel 1 (
        echo.
        echo pip could not install boto3. If this machine is offline, see "Offline install" in README.md.
        pause
        exit /b 1
    )
    rem Optional: lets boto3 read profiles created with `aws login`. Not fatal if it fails.
    "%PY%" -m pip install --disable-pip-version-check -q "botocore[crt]" >nul 2>nul
)

if "%~1"=="" goto :gui
"%PY%" "%HERE%aws_tag_audit.py" %*
exit /b %errorlevel%

:gui
"%PY%" -c "import tkinter" >nul 2>nul
if errorlevel 1 (
    echo Tkinter is missing from this Python. Reinstall Python from python.org with "tcl/tk and IDLE" ticked.
    pause
    exit /b 1
)
rem pythonw = no console window behind the GUI
if exist "%VENV%\Scripts\pythonw.exe" (
    start "" "%VENV%\Scripts\pythonw.exe" "%HERE%aws_tag_audit_gui.py"
) else (
    "%PY%" "%HERE%aws_tag_audit_gui.py"
)
exit /b 0
