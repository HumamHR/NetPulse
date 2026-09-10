@echo off
TITLE NETPULSE IDS - Suricata Launcher
color 0A

:: --- AUTOMATED CONFIGURATION ---
:: Get the directory where this script is running
set SCRIPT_DIR=%~dp0
:: Go up one level to find the Project root
pushd %SCRIPT_DIR%..
set PROJECT_PATH=%CD%
popd

:: --- USER CONFIGURATION ---
set IP_ADDRESS=192.168.1.33

:: Suricata Paths
set SURICATA_BIN="C:\Program Files\Suricata\suricata.exe"
set SURICATA_CONF="C:\Program Files\Suricata\suricata.yaml"

:: 3. Logs - Saves inside the project folder instead of C:\Logs (Better for permissions)
if not exist "%PROJECT_PATH%\logs" mkdir "%PROJECT_PATH%\logs"
set LOG_FILE="%PROJECT_PATH%\logs\fast.log"
set RULES_FILE="%PROJECT_PATH%\pages\rules\suricata_web.rules"

echo ==================================================
echo       STARTING NETPULSE IDS (SURICATA)
echo ==================================================
echo [+] Project Path: %PROJECT_PATH%
echo [+] Interface:    %IP_ADDRESS%
echo [+] Rules:        %RULES_FILE%
echo [+] Log Dir:      %LOG_DIR%
echo.

:: Run the Command
:: We use -l "%LOG_DIR%" to safely pass the folder path (even with spaces).
:: Suricata will automatically create fast.log inside this directory.
%SURICATA_BIN% -c %SURICATA_CONF% -S %RULES_FILE% -i %IP_ADDRESS% -k none -v --set outputs.1.fast.enabled=yes --set outputs.1.fast.filename=%LOG_FILE% --set outputs.1.fast.append=yes

echo.
echo [!] Suricata has stopped. Press any key to close...
pause