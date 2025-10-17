@echo off
REM Batch file to run PowerShell script with IP address argument
REM Usage: run-script.bat <IP_ADDRESS>

REM Check if an argument was provided
if "%1"=="" (
    echo Error: Please provide an IP address as an argument
    echo Usage: %0 ^<IP_ADDRESS^>
    echo Example: %0 192.168.1.100
    exit /b 1
)

REM Store the IP address argument in a variable
set IP_ADDRESS=%1

REM Display the IP address being used
echo Using IP address: %IP_ADDRESS%

.\psexec \\%IP_ADDRESS% -u student -p Training1 -h cmd /c "PowerShell.exe -command "Enable-PSRemoting -Force""

pause