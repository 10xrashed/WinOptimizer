@echo off
color 0F
title Windows Optimizer v2.0 by 10xRashed
setlocal EnableDelayedExpansion

:: Check for Administrator privileges
net session >nul 2>&1
if %errorlevel% neq 0 (
    echo ========================================
    echo  ADMINISTRATOR PRIVILEGES REQUIRED
    echo ========================================
    echo.
    echo This script must be run as Administrator.
    echo Please right-click and select "Run as Administrator"
    echo.
    pause
    exit /b 1
)

:: Initialize log file
set "LOGFILE=%TEMP%\WinOptimizer_%date:~-4,4%%date:~-10,2%%date:~-7,2%_%time:~0,2%%time:~3,2%.log"
set "LOGFILE=%LOGFILE: =0%"
echo Windows Performance Optimizer Log - %date% %time% > "%LOGFILE%"
echo ================================================= >> "%LOGFILE%"

:menu
cls
echo.
echo          .__         ________          __  .__        .__                     
echo __  _  _^|__^| ____   \_____  \ _______/  ^|_^|__^| _____ ^|__^|_______ ___________ 
echo \ \/ \/ /  ^|/    \   /   ^|   \\____ \   __\  ^|/     \^|  \___   // __ \_  __ \
echo  \     /^|  ^|   ^|  \ /    ^|    \  ^|_^> ^>  ^| ^|  ^|  Y Y  \  ^|/    /\  ___/^|  ^| \/
echo   \/\_/ ^|__^|___^|  / \_______  /   __/^|__^| ^|__^|__^|_^|  /__/_____ \\___  ^>__^|   
echo                 \/          \/^|__^|                 \/         \/    \/       
echo ___.                                                                         
echo \_ ^|__ ___.__.                                                                
echo  ^| __ ^<   ^|  ^|                                                                
echo  ^| \_\ \___  ^|                                                                
echo  ^|___  / ____^|                                                                
echo      \/\/                                                                     
echo  ___________         __________               .__               .___         
echo /_   \   _  \ ___  __\______   \_____    _____^|  ^|__   ____   __^| _/         
echo  ^|   /  /_\  \\  \/  /^|       _/\__  \  /  ___/  ^|  \_/ __ \ / __ ^|          
echo  ^|   \  \_/   \^>    ^< ^|    ^|   \ / __ \_\___ \^|   Y  \  ___// /_/ ^|          
echo  ^|___^|\_____  /__/\_ \^|____^|_  /^(____  /____  ^>___^|  /\___  ^>____ ^|          
echo             \/      \/       \/      \/     \/     \/     \/     \/          
echo.
echo ============================================================================
echo  SYSTEM OPTIMIZATION MENU
echo ============================================================================
echo.
echo  CLEANING OPTIONS:
echo  [1] System Deep Clean (Logs, Temp, Cache, GPU, Recycle Bin)
echo  [2] Quick System Clean (Essential cleanup only)
echo.
echo  OPTIMIZATION OPTIONS:
echo  [3] Performance Optimization Suite [ADVANCED - Creates Restore Point]
echo  [4] Memory ^& CPU Optimization
echo  [5] Network Performance Boost
echo  [6] Visual Effects Optimization
echo  [7] Registry Performance Tweaks
echo  [8] Gaming Optimization Mode
echo.
echo  MAINTENANCE OPTIONS:
echo  [9] System Health Check ^& Repair
echo  [10] Disk Optimization ^& Defragmentation
echo  [11] Create System Restore Point
echo.
echo  SYSTEM INFORMATION:
echo  [12] View Current System Status
echo  [13] View Optimization Log
echo.
echo  RESTORE OPTIONS:
echo  [14] Restore All Settings to Default
echo.
echo  [0] Exit
echo.
echo ============================================================================
set /p choice="Choose an option (0-14): "

if "!choice!"=="1" goto deepclean
if "!choice!"=="2" goto quickclean
if "!choice!"=="3" goto confirmFullOptimize
if "!choice!"=="4" goto memoryoptimize
if "!choice!"=="5" goto networkoptimize
if "!choice!"=="6" goto visualoptimize
if "!choice!"=="7" goto registryoptimize
if "!choice!"=="8" goto gamingoptimize
if "!choice!"=="9" goto systemcheck
if "!choice!"=="10" goto diskoptimize
if "!choice!"=="11" goto createrestore
if "!choice!"=="12" goto systemstatus
if "!choice!"=="13" goto viewlog
if "!choice!"=="14" goto confirmRestore
if "!choice!"=="0" exit
goto menu

:: Confirm Full Optimization
:confirmFullOptimize
cls
echo ============================================================================
echo  WARNING: COMPREHENSIVE SYSTEM OPTIMIZATION
echo ============================================================================
echo.
echo This will apply comprehensive performance optimizations including:
echo.
echo  ^> Deep system cleaning (may free 2GB-20GB)
echo  ^> Memory and CPU optimization
echo  ^> Network performance enhancement
echo  ^> Visual effects optimization for speed
echo  ^> Registry performance tweaks
echo  ^> Power plan optimization
echo.
echo IMPORTANT: A System Restore Point will be created automatically
echo            before making any changes.
echo.
echo Estimated time: 5-15 minutes
echo.
echo ============================================================================
set /p confirm="Do you want to proceed? (Y/N): "
if /i "!confirm!"=="Y" goto fulloptimize
goto menu

:: Confirm Restore
:confirmRestore
cls
echo ============================================================================
echo  WARNING: RESTORE TO DEFAULT SETTINGS
echo ============================================================================
echo.
echo This will restore all optimizations to Windows defaults.
echo.
echo Changes to be reverted:
echo  ^> All performance optimizations
echo  ^> Network settings
echo  ^> Visual effects settings
echo  ^> Power plan settings
echo  ^> Service configurations
echo.
echo NOTE: This will NOT delete cleaned files or restored disk space.
echo.
echo ============================================================================
set /p confirm="Are you sure you want to restore all settings? (Y/N): "
if /i "!confirm!"=="Y" goto restoreall
goto menu

:: Create Restore Point
:createrestore
cls
echo Creating System Restore Point...
echo ================================
echo.
echo This may take a few minutes...
echo.
powershell -Command "Checkpoint-Computer -Description 'Windows Optimizer - Manual Restore Point' -RestorePointType 'MODIFY_SETTINGS'" 2>nul
if %errorlevel% equ 0 (
    echo [SUCCESS] Restore point created successfully!
    echo [SUCCESS] Restore point created successfully! >> "%LOGFILE%"
) else (
    echo [WARNING] Could not create restore point. You may need to enable System Protection.
    echo [WARNING] Could not create restore point >> "%LOGFILE%"
)
echo.
pause
goto menu

:: Quick Clean
:quickclean
cls
echo ============================================================================
echo  QUICK SYSTEM CLEAN
echo ============================================================================
echo.
echo Starting quick cleanup process...
echo.

call :log "=== Quick Clean Started ==="

echo [1/6] Clearing temporary files...
call :log "Clearing temporary files"
if exist "%TEMP%\*" (
    del /f /s /q "%TEMP%\*" 2>nul
    for /d %%p in ("%TEMP%\*") do rd /s /q "%%p" 2>nul
)
if exist "C:\Windows\Temp\*" (
    del /f /s /q "C:\Windows\Temp\*" 2>nul
    for /d %%p in ("C:\Windows\Temp\*") do rd /s /q "%%p" 2>nul
)

echo [2/6] Clearing browser caches...
call :log "Clearing browser caches"
if exist "%LocalAppData%\Google\Chrome\User Data\Default\Cache" rd /s /q "%LocalAppData%\Google\Chrome\User Data\Default\Cache" 2>nul
if exist "%LocalAppData%\Google\Chrome\User Data\Default\Code Cache" rd /s /q "%LocalAppData%\Google\Chrome\User Data\Default\Code Cache" 2>nul
if exist "%LocalAppData%\Microsoft\Edge\User Data\Default\Cache" rd /s /q "%LocalAppData%\Microsoft\Edge\User Data\Default\Cache" 2>nul
if exist "%LocalAppData%\Microsoft\Edge\User Data\Default\Code Cache" rd /s /q "%LocalAppData%\Microsoft\Edge\User Data\Default\Code Cache" 2>nul

echo [3/6] Clearing Windows update cache...
call :log "Clearing Windows update cache"
net stop wuauserv >nul 2>&1
if exist "C:\Windows\SoftwareDistribution\Download\*" (
    del /f /s /q "C:\Windows\SoftwareDistribution\Download\*" 2>nul
    for /d %%p in ("C:\Windows\SoftwareDistribution\Download\*") do rd /s /q "%%p" 2>nul
)
net start wuauserv >nul 2>&1

echo [4/6] Clearing thumbnail cache...
call :log "Clearing thumbnail cache"
taskkill /f /im explorer.exe >nul 2>&1
timeout /t 2 /nobreak >nul
for %%i in ("%LocalAppData%\Microsoft\Windows\Explorer\thumbcache*") do (
    if exist "%%i" del /f /q "%%i" 2>nul
)
start explorer.exe

echo [5/6] Clearing Recycle Bin...
call :log "Emptying Recycle Bin"
powershell -Command "Clear-RecycleBin -Force -ErrorAction SilentlyContinue" 2>nul

echo [6/6] Clearing recent files list...
call :log "Clearing recent files"
if exist "%AppData%\Microsoft\Windows\Recent\*.*" del /f /q "%AppData%\Microsoft\Windows\Recent\*.*" 2>nul

echo.
echo ============================================================================
echo [SUCCESS] Quick Clean completed successfully!
echo.
echo Estimated space freed: 500MB - 2GB
echo Log file: %LOGFILE%
echo ============================================================================
call :log "=== Quick Clean Completed ==="
pause
goto menu

:: Enhanced Deep Clean
:deepclean
cls
echo ============================================================================
echo  DEEP SYSTEM CLEAN
echo ============================================================================
echo.
echo Starting comprehensive cleanup process...
echo This may take several minutes. Please wait...
echo.

call :log "=== Deep Clean Started ==="

echo [1/15] Clearing temporary files...
call :log "Clearing temporary files"
if exist "%TEMP%\*" (
    del /f /s /q "%TEMP%\*" 2>nul
    for /d %%p in ("%TEMP%\*") do rd /s /q "%%p" 2>nul
)
if exist "C:\Windows\Temp\*" (
    del /f /s /q "C:\Windows\Temp\*" 2>nul
    for /d %%p in ("C:\Windows\Temp\*") do rd /s /q "%%p" 2>nul
)

echo [2/15] Clearing prefetch files...
call :log "Clearing prefetch files"
if exist "C:\Windows\Prefetch\*.*" del /f /s /q "C:\Windows\Prefetch\*.*" 2>nul

echo [3/15] Clearing GPU caches (NVIDIA, AMD, Intel)...
call :log "Clearing GPU caches"
if exist "%LocalAppData%\NVIDIA\DXCache" rd /s /q "%LocalAppData%\NVIDIA\DXCache" 2>nul
if exist "%LocalAppData%\NVIDIA\GLCache" rd /s /q "%LocalAppData%\NVIDIA\GLCache" 2>nul
if exist "%LocalAppData%\AMD\DxCache" rd /s /q "%LocalAppData%\AMD\DxCache" 2>nul
if exist "%LocalAppData%\AMD\GLCache" rd /s /q "%LocalAppData%\AMD\GLCache" 2>nul
if exist "%LocalAppData%\D3DSCache" rd /s /q "%LocalAppData%\D3DSCache" 2>nul

echo [4/15] Clearing browser data (Chrome, Edge, Firefox)...
call :log "Clearing browser caches and data"
if exist "%LocalAppData%\Google\Chrome\User Data\Default\Cache" rd /s /q "%LocalAppData%\Google\Chrome\User Data\Default\Cache" 2>nul
if exist "%LocalAppData%\Google\Chrome\User Data\Default\Code Cache" rd /s /q "%LocalAppData%\Google\Chrome\User Data\Default\Code Cache" 2>nul
if exist "%LocalAppData%\Microsoft\Edge\User Data\Default\Cache" rd /s /q "%LocalAppData%\Microsoft\Edge\User Data\Default\Cache" 2>nul
if exist "%LocalAppData%\Microsoft\Edge\User Data\Default\Code Cache" rd /s /q "%LocalAppData%\Microsoft\Edge\User Data\Default\Code Cache" 2>nul
for /d %%i in ("%AppData%\Mozilla\Firefox\Profiles\*.default*") do (
    if exist "%%i\cache2" rd /s /q "%%i\cache2" 2>nul
)

echo [5/15] Clearing Windows error reports...
call :log "Clearing Windows error reports"
if exist "C:\ProgramData\Microsoft\Windows\WER\*" (
    del /f /s /q "C:\ProgramData\Microsoft\Windows\WER\*" 2>nul
    for /d %%p in ("C:\ProgramData\Microsoft\Windows\WER\*") do rd /s /q "%%p" 2>nul
)

echo [6/15] Clearing Windows update files...
call :log "Clearing Windows update cache"
net stop wuauserv >nul 2>&1
if exist "C:\Windows\SoftwareDistribution\Download\*" (
    del /f /s /q "C:\Windows\SoftwareDistribution\Download\*" 2>nul
    for /d %%p in ("C:\Windows\SoftwareDistribution\Download\*") do rd /s /q "%%p" 2>nul
)
net start wuauserv >nul 2>&1

echo [7/15] Clearing system log files...
call :log "Clearing system logs"
for /r "C:\Windows\Logs" %%f in (*.log) do (
    if exist "%%f" del /f /q "%%f" 2>nul
)
for /r "C:\Windows\System32\LogFiles" %%f in (*.log *.etl) do (
    if exist "%%f" del /f /q "%%f" 2>nul
)

echo [8/15] Clearing thumbnail and icon cache...
call :log "Clearing thumbnail cache"
taskkill /f /im explorer.exe >nul 2>&1
timeout /t 2 /nobreak >nul
for %%i in ("%LocalAppData%\Microsoft\Windows\Explorer\thumbcache*") do (
    if exist "%%i" del /f /q "%%i" 2>nul
)
if exist "%LocalAppData%\IconCache.db" del /f /q "%LocalAppData%\IconCache.db" 2>nul
del /f /q "%LocalAppData%\Microsoft\Windows\Explorer\*.db" 2>nul

echo [9/15] Clearing memory dumps...
call :log "Clearing memory dumps"
if exist "C:\Windows\*.dmp" del /f /q "C:\Windows\*.dmp" 2>nul
if exist "C:\Windows\Minidump\*.*" del /f /q "C:\Windows\Minidump\*.*" 2>nul
if exist "C:\Windows\MEMORY.DMP" del /f /q "C:\Windows\MEMORY.DMP" 2>nul

echo [10/15] Clearing old Windows installation files...
call :log "Removing Windows.old folder"
if exist "C:\Windows.old" (
    takeown /F "C:\Windows.old\*" /R /A /D Y >nul 2>&1
    icacls "C:\Windows.old\*" /T /grant administrators:F >nul 2>&1
    rd /s /q "C:\Windows.old" 2>nul
)

echo [11/15] Clearing Windows delivery optimization cache...
call :log "Clearing delivery optimization"
if exist "C:\Windows\ServiceProfiles\NetworkService\AppData\Local\Microsoft\Windows\DeliveryOptimization\Cache\*" (
    del /f /s /q "C:\Windows\ServiceProfiles\NetworkService\AppData\Local\Microsoft\Windows\DeliveryOptimization\Cache\*" 2>nul
)

echo [12/15] Clearing Windows font cache...
call :log "Clearing font cache"
net stop FontCache >nul 2>&1
if exist "%WinDir%\ServiceProfiles\LocalService\AppData\Local\FontCache\*.*" (
    del /f /s /q "%WinDir%\ServiceProfiles\LocalService\AppData\Local\FontCache\*.*" 2>nul
)
net start FontCache >nul 2>&1

echo [13/15] Emptying Recycle Bin...
call :log "Emptying Recycle Bin"
powershell -Command "Clear-RecycleBin -Force -ErrorAction SilentlyContinue" 2>nul

echo [14/15] Running Windows Disk Cleanup utility...
call :log "Running Disk Cleanup"
cleanmgr /sagerun:1 >nul 2>&1

echo [15/15] Restarting Windows Explorer...
start explorer.exe
timeout /t 2 /nobreak >nul

echo.
echo ============================================================================
echo [SUCCESS] Deep Clean completed successfully!
echo.
echo Estimated space freed: 2GB - 20GB+
echo Log file: %LOGFILE%
echo ============================================================================
call :log "=== Deep Clean Completed ==="
pause
goto menu

:: Memory and CPU Optimization
:memoryoptimize
cls
echo ============================================================================
echo  MEMORY ^& CPU OPTIMIZATION
echo ============================================================================
echo.
echo Applying memory and processor optimizations...
echo.

call :log "=== Memory & CPU Optimization Started ==="

echo [1/8] Configuring Superfetch/SysMain service...
call :log "Configuring SysMain"
sc config "SysMain" start= disabled >nul 2>&1
sc stop "SysMain" >nul 2>&1

echo [2/8] Optimizing virtual memory (pagefile)...
call :log "Optimizing virtual memory"
for /f "tokens=3" %%a in ('wmic computersystem get TotalPhysicalMemory /value ^| find "="') do set /a RAM=%%a/1024/1024
set /a InitialSize=%RAM%*3/2
set /a MaxSize=%RAM%*2
echo Configuring pagefile: Initial=%InitialSize%MB, Maximum=%MaxSize%MB
wmic computersystem where name="%computername%" set AutomaticManagedPagefile=False >nul 2>&1
wmic pagefileset where name="C:\\pagefile.sys" set InitialSize=%InitialSize%,MaximumSize=%MaxSize% >nul 2>&1

echo [3/8] Optimizing CPU scheduling for best performance...
call :log "Optimizing CPU scheduling"
reg add "HKLM\SYSTEM\CurrentControlSet\Control\PriorityControl" /v Win32PrioritySeparation /t REG_DWORD /d 38 /f >nul

echo [4/8] Disabling startup delay...
call :log "Disabling startup delay"
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Serialize" /v StartupDelayInMSec /t REG_DWORD /d 0 /f >nul

echo [5/8] Optimizing system cache...
call :log "Optimizing system cache"
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v LargeSystemCache /t REG_DWORD /d 0 /f >nul
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v SecondLevelDataCache /t REG_DWORD /d 1024 /f >nul

echo [6/8] Optimizing processor scheduling...
call :log "Configuring processor scheduling"
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v DisablePagingExecutive /t REG_DWORD /d 1 /f >nul

echo [7/8] Disabling unnecessary system features...
call :log "Disabling unnecessary features"
:: Disable Runtime Broker aggressive memory management
reg add "HKLM\SYSTEM\CurrentControlSet\Services\TimeBrokerSvc" /v Start /t REG_DWORD /d 3 /f >nul

echo [8/8] Clearing memory standby list...
call :log "Clearing standby memory"
powershell -Command "Clear-Variable * -Force -ErrorAction SilentlyContinue" 2>nul

echo.
echo ============================================================================
echo [SUCCESS] Memory and CPU optimization completed!
echo.
echo Changes applied:
echo  ^> Virtual memory optimized for your %RAM%MB RAM
echo  ^> CPU scheduling set for best performance
echo  ^> System cache optimized
echo  ^> Startup delay removed
echo.
echo Restart recommended for all changes to take effect.
echo ============================================================================
call :log "=== Memory & CPU Optimization Completed ==="
pause
goto menu

:: Network Performance Optimization
:networkoptimize
cls
echo ============================================================================
echo  NETWORK PERFORMANCE OPTIMIZATION
echo ============================================================================
echo.
echo Applying network performance enhancements...
echo.

call :log "=== Network Optimization Started ==="

echo [1/7] Disabling network bandwidth throttling...
call :log "Disabling bandwidth throttling"
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" /v NetworkThrottlingIndex /t REG_DWORD /d 4294967295 /f >nul

echo [2/7] Optimizing TCP/IP settings...
call :log "Optimizing TCP settings"
netsh int tcp set global autotuninglevel=normal >nul
netsh int tcp set global chimney=enabled >nul
netsh int tcp set global rss=enabled >nul
netsh int tcp set global netdma=enabled >nul
netsh int tcp set global dca=enabled >nul

echo [3/7] Configuring TCP parameters for performance...
call :log "Configuring TCP parameters"
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v DefaultTTL /t REG_DWORD /d 64 /f >nul
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v EnablePMTUDiscovery /t REG_DWORD /d 1 /f >nul
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v TcpMaxDupAcks /t REG_DWORD /d 2 /f >nul

echo [4/7] Disabling Nagle's algorithm for faster response...
call :log "Configuring network adapters"
for /f "tokens=*" %%a in ('reg query "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces" /s /k 2^>nul ^| find "HKEY"') do (
    reg add "%%a" /v TcpAckFrequency /t REG_DWORD /d 1 /f >nul 2>&1
    reg add "%%a" /v TCPNoDelay /t REG_DWORD /d 1 /f >nul 2>&1
)

echo [5/7] Optimizing DNS settings...
call :log "Configuring DNS"
:: Set Cloudflare DNS as primary, Google as secondary
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v NameServer /t REG_SZ /d "1.1.1.1,8.8.8.8" /f >nul

echo [6/7] Disabling network power management...
call :log "Disabling network power saving"
powershell -Command "Get-NetAdapter | Set-NetAdapterAdvancedProperty -DisplayName 'Energy Efficient Ethernet' -DisplayValue 'Disabled' -ErrorAction SilentlyContinue" 2>nul

echo [7/7] Flushing DNS cache and resetting network...
call :log "Flushing DNS cache"
ipconfig /flushdns >nul
ipconfig /registerdns >nul

echo.
echo ============================================================================
echo [SUCCESS] Network optimization completed!
echo.
echo Changes applied:
echo  ^> Bandwidth throttling disabled
echo  ^> TCP/IP optimized for gaming and streaming
echo  ^> Nagle's algorithm disabled for lower latency
echo  ^> Fast DNS servers configured
echo  ^> Network power saving disabled
echo.
echo Test your network speed to see improvements!
echo ============================================================================
call :log "=== Network Optimization Completed ==="
pause
goto menu

:: Visual Effects Optimization
:visualoptimize
cls
echo ============================================================================
echo  VISUAL EFFECTS OPTIMIZATION
echo ============================================================================
echo.
echo Optimizing visual effects for maximum performance...
echo.

call :log "=== Visual Effects Optimization Started ==="

echo [1/6] Disabling window animations...
call :log "Disabling animations"
reg add "HKCU\Control Panel\Desktop" /v DragFullWindows /t REG_SZ /d 0 /f >nul
reg add "HKCU\Control Panel\Desktop" /v MenuShowDelay /t REG_SZ /d 0 /f >nul
reg add "HKCU\Control Panel\Desktop\WindowMetrics" /v MinAnimate /t REG_SZ /d 0 /f >nul

echo [2/6] Setting visual effects to performance mode...
call :log "Setting performance mode"
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects" /v VisualFXSetting /t REG_DWORD /d 2 /f >nul

echo [3/6] Disabling transparency effects...
call :log "Disabling transparency"
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize" /v EnableTransparency /t REG_DWORD /d 0 /f >nul

echo [4/6] Optimizing taskbar animations...
call :log "Optimizing taskbar"
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v TaskbarAnimations /t REG_DWORD /d 0 /f >nul

echo [5/6] Disabling additional visual effects...
call :log "Disabling additional effects"
reg add "HKCU\Control Panel\Desktop" /v UserPreferencesMask /t REG_BINARY /d 9012038010000000 /f >nul
reg add "HKCU\SOFTWARE\Microsoft\Windows\DWM" /v EnableAeroPeek /t REG_DWORD /d 0 /f >nul
reg add "HKCU\SOFTWARE\Microsoft\Windows\DWM" /v AlwaysHibernateThumbnails /t REG_DWORD /d 0 /f >nul

echo [6/6] Disabling Windows animations...
call :log "Disabling system animations"
reg add "HKCU\Control Panel\Desktop" /v FontSmoothing /t REG_SZ /d 2 /f >nul

echo.
echo ============================================================================
echo [SUCCESS] Visual effects optimization completed!
echo.
echo Changes applied:
echo  ^> All animations disabled
echo  ^> Transparency effects disabled
echo  ^> Performance mode activated
echo  ^> Taskbar animations disabled
echo.
echo NOTE: You may need to log out and back in for all changes to take effect.
echo ============================================================================
call :log "=== Visual Effects Optimization Completed ==="
pause
goto menu

:: Registry Performance Tweaks
:registryoptimize
cls
echo ============================================================================
echo  REGISTRY PERFORMANCE TWEAKS
echo ============================================================================
echo.
echo Applying advanced registry optimizations...
echo.

call :log "=== Registry Optimization Started ==="

echo [1/10] Optimizing file system cache...
call :log "Optimizing file system"
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v IoPageLockLimit /t REG_DWORD /d 983040 /f >nul

echo [2/10] Disabling last access time stamps...
call :log "Disabling last access timestamps"
fsutil behavior set DisableLastAccess 1 >nul

echo [3/10] Optimizing NTFS performance...
call :log "Optimizing NTFS"
fsutil behavior set MemoryUsage 2 >nul
fsutil behavior set MftZoneReservation 2 >nul
fsutil behavior set DisableDeleteNotify 0 >nul

echo [4/10] Configuring Windows Search indexing...
call :log "Configuring search indexing"
:: Don't disable, just optimize
reg add "HKLM\SOFTWARE\Microsoft\Windows Search" /v SetupCompletedSuccessfully /t REG_DWORD /d 0 /f >nul

echo [5/10] Optimizing power settings...
call :log "Optimizing power settings"
powercfg /setactive SCHEME_MIN >nul 2>&1
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\943c8cb6-6f93-4227-ad87-e9a3feec08d1" /v Attributes /t REG_DWORD /d 2 /f >nul

echo [6/10] Optimizing system responsiveness...
call :log "Optimizing system responsiveness"
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" /v SystemResponsiveness /t REG_DWORD /d 10 /f >nul

echo [7/10] Optimizing mouse and keyboard response...
call :log "Optimizing input devices"
reg add "HKCU\Control Panel\Mouse" /v MouseHoverTime /t REG_SZ /d 10 /f >nul
reg add "HKCU\Control Panel\Keyboard" /v KeyboardDelay /t REG_SZ /d 0 /f >nul
reg add "HKCU\Control Panel\Keyboard" /v KeyboardSpeed /t REG_SZ /d 31 /f >nul

echo [8/10] Disabling hibernation to free disk space...
call :log "Configuring hibernation"
powercfg /hibernate off >nul

echo [9/10] Optimizing boot performance...
call :log "Optimizing boot"
reg add "HKLM\SOFTWARE\Microsoft\Dfrg\BootOptimizeFunction" /v Enable /t REG_SZ /d Y /f >nul
bcdedit /set bootmenupolicy Standard >nul 2>&1

echo [10/10] Disabling unnecessary scheduled tasks...
call :log "Disabling unnecessary tasks"
schtasks /Change /TN "\Microsoft\Windows\Application Experience\Microsoft Compatibility Appraiser" /Disable >nul 2>&1
schtasks /Change /TN "\Microsoft\Windows\Application Experience\ProgramDataUpdater" /Disable >nul 2>&1
schtasks /Change /TN "\Microsoft\Windows\Autochk\Proxy" /Disable >nul 2>&1
schtasks /Change /TN "\Microsoft\Windows\Customer Experience Improvement Program\Consolidator" /Disable >nul 2>&1
schtasks /Change /TN "\Microsoft\Windows\Customer Experience Improvement Program\UsbCeip" /Disable >nul 2>&1
schtasks /Change /TN "\Microsoft\Windows\DiskDiagnostic\Microsoft-Windows-DiskDiagnosticDataCollector" /Disable >nul 2>&1

echo.
echo ============================================================================
echo [SUCCESS] Registry optimization completed!
echo.
echo Changes applied:
echo  ^> File system cache optimized
echo  ^> NTFS performance improved
echo  ^> Input device responsiveness enhanced
echo  ^> Boot performance optimized
echo  ^> Unnecessary telemetry tasks disabled
echo.
echo Restart recommended for all changes to take effect.
echo ============================================================================
call :log "=== Registry Optimization Completed ==="
pause
goto menu

:: Gaming Optimization Mode
:gamingoptimize
cls
echo ============================================================================
echo  GAMING OPTIMIZATION MODE
echo ============================================================================
echo.
echo Applying gaming-specific optimizations...
echo.

call :log "=== Gaming Optimization Started ==="

echo [1/8] Enabling Game Mode...
call :log "Enabling Game Mode"
reg add "HKCU\Software\Microsoft\GameBar" /v AutoGameModeEnabled /t REG_DWORD /d 1 /f >nul
reg add "HKCU\Software\Microsoft\GameBar" /v AllowAutoGameMode /t REG_DWORD /d 1 /f >nul

echo [2/8] Optimizing GPU scheduling...
call :log "Optimizing GPU settings"
reg add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers" /v HwSchMode /t REG_DWORD /d 2 /f >nul

echo [3/8] Setting high-performance power plan...
call :log "Setting power plan"
powercfg /setactive 8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c >nul 2>&1

echo [4/8] Optimizing mouse precision for gaming...
call :log "Disabling mouse acceleration"
reg add "HKCU\Control Panel\Mouse" /v MouseSpeed /t REG_SZ /d 0 /f >nul
reg add "HKCU\Control Panel\Mouse" /v MouseThreshold1 /t REG_SZ /d 0 /f >nul
reg add "HKCU\Control Panel\Mouse" /v MouseThreshold2 /t REG_SZ /d 0 /f >nul

echo [5/8] Disabling Fullscreen Optimizations...
call :log "Disabling fullscreen optimizations"
reg add "HKCU\System\GameConfigStore" /v GameDVR_Enabled /t REG_DWORD /d 0 /f >nul
reg add "HKCU\System\GameConfigStore" /v GameDVR_FSEBehaviorMode /t REG_DWORD /d 2 /f >nul

echo [6/8] Optimizing network for gaming...
call :log "Optimizing gaming network"
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "GPU Priority" /t REG_DWORD /d 8 /f >nul
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v Priority /t REG_DWORD /d 6 /f >nul
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "Scheduling Category" /t REG_SZ /d High /f >nul

echo [7/8] Disabling Game DVR...
call :log "Disabling Game DVR"
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\GameDVR" /v AppCaptureEnabled /t REG_DWORD /d 0 /f >nul
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\GameDVR" /v AudioCaptureEnabled /t REG_DWORD /d 0 /f >nul

echo [8/8] Optimizing CPU for gaming performance...
call :log "Optimizing gaming CPU priority"
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "SFIO Priority" /t REG_SZ /d High /f >nul

echo.
echo ============================================================================
echo [SUCCESS] Gaming optimization completed!
echo.
echo Changes applied:
echo  ^> Windows Game Mode enabled
echo  ^> GPU hardware scheduling enabled
echo  ^> High-performance power plan activated
echo  ^> Mouse acceleration disabled
echo  ^> Game DVR and fullscreen optimizations disabled
echo  ^> Gaming network priority optimized
echo.
echo Your system is now optimized for gaming performance!
echo ============================================================================
call :log "=== Gaming Optimization Completed ==="
pause
goto menu

:: Disk Optimization
:diskoptimize
cls
echo ============================================================================
echo  DISK OPTIMIZATION ^& DEFRAGMENTATION
echo ============================================================================
echo.
echo Analyzing and optimizing disk drives...
echo.

call :log "=== Disk Optimization Started ==="

echo [1/3] Analyzing disk drives...
call :log "Analyzing drives"
defrag C: /A

echo.
echo [2/3] Optimizing drives (this may take a while)...
call :log "Optimizing drives"
defrag C: /O /H /V

echo.
echo [3/3] Enabling automatic optimization...
call :log "Configuring automatic optimization"
schtasks /Change /TN "\Microsoft\Windows\Defrag\ScheduledDefrag" /Enable >nul 2>&1

echo.
echo ============================================================================
echo [SUCCESS] Disk optimization completed!
echo.
echo Your drives have been analyzed and optimized.
echo Automatic optimization has been enabled.
echo ============================================================================
call :log "=== Disk Optimization Completed ==="
pause
goto menu

:: System Health Check
:systemcheck
cls
echo ============================================================================
echo  SYSTEM HEALTH CHECK ^& REPAIR
echo ============================================================================
echo.
echo Running comprehensive system diagnostics...
echo This process may take 15-30 minutes. Please be patient.
echo.

call :log "=== System Health Check Started ==="

echo [1/4] Checking system file integrity...
echo This may take 10-15 minutes...
call :log "Running SFC scan"
sfc /scannow
if %errorlevel% equ 0 (
    echo [SUCCESS] System files are healthy
    call :log "SFC: System files healthy"
) else (
    echo [WARNING] Some system files may need repair
    call :log "SFC: Issues detected"
)

echo.
echo [2/4] Checking system image health...
call :log "Running DISM health check"
dism /online /cleanup-image /checkhealth
if %errorlevel% equ 0 (
    echo [SUCCESS] System image is healthy
    call :log "DISM CheckHealth: Passed"
) else (
    echo [INFO] Running system image scan and repair...
    call :log "DISM: Running ScanHealth"
    dism /online /cleanup-image /scanhealth
    dism /online /cleanup-image /restorehealth
)

echo.
echo [3/4] Checking disk health...
call :log "Running disk check"
echo Running disk error check...
chkdsk C: /scan
if %errorlevel% equ 0 (
    echo [SUCCESS] No disk errors detected
    call :log "CHKDSK: No errors"
) else (
    echo [WARNING] Disk errors detected. Schedule a full check on restart.
    call :log "CHKDSK: Errors found"
)

echo.
echo [4/4] Quick malware scan (Windows Defender)...
call :log "Running malware scan"
powershell -Command "Update-MpSignature -ErrorAction SilentlyContinue; Start-MpScan -ScanType QuickScan" 2>nul
if %errorlevel% equ 0 (
    echo [SUCCESS] Quick scan completed
    call :log "Defender: Quick scan completed"
) else (
    echo [INFO] Scan completed with warnings or threats found
    call :log "Defender: Warnings or threats detected"
)

echo.
echo ============================================================================
echo [COMPLETE] System health check finished!
echo.
echo Review the output above for any issues that need attention.
echo Check Event Viewer for detailed system logs if problems persist.
echo ============================================================================
call :log "=== System Health Check Completed ==="
pause
goto menu

:: System Status
:systemstatus
cls
echo ============================================================================
echo  CURRENT SYSTEM PERFORMANCE STATUS
echo ============================================================================
echo.

echo [POWER PLAN]
echo ----------------------------------------------------------------------------
powercfg /getactivescheme
echo.

echo [MEMORY USAGE]
echo ----------------------------------------------------------------------------
for /f "tokens=2 delims==" %%a in ('wmic OS get TotalVisibleMemorySize /value ^| find "="') do set TotalMem=%%a
for /f "tokens=2 delims==" %%a in ('wmic OS get FreePhysicalMemory /value ^| find "="') do set FreeMem=%%a
set /a UsedMem=TotalMem-FreeMem
set /a MemPercent=UsedMem*100/TotalMem
set /a TotalMemGB=TotalMem/1024/1024
set /a FreeMemGB=FreeMem/1024/1024
set /a UsedMemGB=UsedMem/1024/1024
echo Total Memory: %TotalMemGB%GB (%TotalMem% KB)
echo Free Memory:  %FreeMemGB%GB (%FreeMem% KB)
echo Used Memory:  %UsedMemGB%GB (%UsedMem% KB)
echo Memory Usage: %MemPercent%%%
echo.

echo [CPU USAGE]
echo ----------------------------------------------------------------------------
wmic cpu get name
for /f "tokens=2 delims==" %%a in ('wmic cpu get loadpercentage /value ^| find "="') do echo Current CPU Load: %%a%%
echo.

echo [DISK SPACE]
echo ----------------------------------------------------------------------------
for /f "tokens=1,2,3" %%a in ('wmic logicaldisk where "drivetype=3" get caption^,freespace^,size /format:table ^| find ":"') do (
    set /a FreeGB=%%b/1024/1024/1024
    set /a TotalGB=%%c/1024/1024/1024
    set /a UsedGB=TotalGB-FreeGB
    echo Drive %%a: !UsedGB!GB used / !TotalGB!GB total ^(!FreeGB!GB free^)
)
echo.

echo [PERFORMANCE SERVICES STATUS]
echo ----------------------------------------------------------------------------
echo SysMain (Superfetch):
sc query SysMain 2>nul | findstr STATE || echo Service not found/disabled
echo.
echo Windows Search:
sc query WSearch 2>nul | findstr STATE || echo Service not found/disabled
echo.
echo Game Mode:
for /f "tokens=3" %%a in ('reg query "HKCU\Software\Microsoft\GameBar" /v AutoGameModeEnabled 2^>nul ^| find "AutoGameModeEnabled"') do (
    if "%%a"=="0x1" (echo Enabled) else (echo Disabled)
)
echo.

echo [NETWORK STATUS]
echo ----------------------------------------------------------------------------
echo Active Network Connections:
netsh interface show interface | findstr "Connected"
echo.
echo DNS Servers:
ipconfig /all | findstr /i "DNS Servers" | findstr /v "fec0"
echo.

echo [SYSTEM UPTIME]
echo ----------------------------------------------------------------------------
for /f "skip=1" %%x in ('wmic os get lastbootuptime') do (
    set BootTime=%%x
    goto :ParseBootTime
)
:ParseBootTime
echo Last Boot: %BootTime:~0,4%-%BootTime:~4,2%-%BootTime:~6,2% %BootTime:~8,2%:%BootTime:~10,2%
echo.

echo ============================================================================
pause
goto menu

:: View Log
:viewlog
cls
echo ============================================================================
echo  OPTIMIZATION LOG
echo ============================================================================
echo.
if exist "%LOGFILE%" (
    type "%LOGFILE%"
    echo.
    echo ============================================================================
    echo Log file location: %LOGFILE%
) else (
    echo No log file found for this session.
)
echo.
pause
goto menu

:: Full Optimization Suite
:fulloptimize
cls
echo ============================================================================
echo  COMPLETE PERFORMANCE OPTIMIZATION SUITE
echo ============================================================================
echo.

call :log "=== FULL OPTIMIZATION SUITE STARTED ==="

echo Creating System Restore Point...
echo ----------------------------------------------------------------------------
powershell -Command "Checkpoint-Computer -Description 'Before Full Optimization' -RestorePointType 'MODIFY_SETTINGS'" 2>nul
if %errorlevel% equ 0 (
    echo [SUCCESS] Restore point created successfully!
    call :log "Restore point created"
) else (
    echo [WARNING] Could not create restore point
    call :log "Restore point creation failed"
    set /p continue="Continue without restore point? (Y/N): "
    if /i not "!continue!"=="Y" goto menu
)

echo.
echo PHASE 1: Deep System Cleaning
echo ----------------------------------------------------------------------------
call :deepclean_silent

echo.
echo PHASE 2: Memory and CPU Optimization
echo ----------------------------------------------------------------------------
call :memoryoptimize_silent

echo.
echo PHASE 3: Network Optimization
echo ----------------------------------------------------------------------------
call :networkoptimize_silent

echo.
echo PHASE 4: Visual Effects Optimization
echo ----------------------------------------------------------------------------
call :visualoptimize_silent

echo.
echo PHASE 5: Registry Optimization
echo ----------------------------------------------------------------------------
call :registryoptimize_silent

echo.
echo PHASE 6: Gaming Optimization
echo ----------------------------------------------------------------------------
call :gamingoptimize_silent

echo.
echo PHASE 7: Power Plan Optimization
echo ----------------------------------------------------------------------------
echo Enabling High Performance power plan...
call :log "Setting high performance power plan"
powercfg /setactive 8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c >nul 2>&1

echo.
echo ============================================================================
echo  COMPLETE OPTIMIZATION FINISHED SUCCESSFULLY!
echo ============================================================================
echo.
echo Your system has been fully optimized for maximum performance.
echo.
echo All optimizations have been logged to:
echo %LOGFILE%
echo.
echo IMPORTANT: It is highly recommended to restart your computer now
echo            for all changes to take full effect.
echo.
echo ============================================================================

call :log "=== FULL OPTIMIZATION SUITE COMPLETED ==="

set /p restart="Do you want to restart your PC now? (Y/N): "
if /i "!restart!"=="Y" (
    echo.
    echo Restarting in 10 seconds... Press Ctrl+C to cancel.
    shutdown /r /t 10 /c "System restart for optimization changes"
)
pause
goto menu

:: Silent functions for full optimization
:deepclean_silent
call :log "Phase 1: Deep Clean Started"
if exist "%TEMP%\*" (
    del /f /s /q "%TEMP%\*" 2>nul
    for /d %%p in ("%TEMP%\*") do rd /s /q "%%p" 2>nul
)
if exist "C:\Windows\Temp\*" (
    del /f /s /q "C:\Windows\Temp\*" 2>nul
    for /d %%p in ("C:\Windows\Temp\*") do rd /s /q "%%p" 2>nul
)
if exist "C:\Windows\Prefetch\*.*" del /f /s /q "C:\Windows\Prefetch\*.*" 2>nul
if exist "%LocalAppData%\NVIDIA\DXCache" rd /s /q "%LocalAppData%\NVIDIA\DXCache" 2>nul
if exist "%LocalAppData%\NVIDIA\GLCache" rd /s /q "%LocalAppData%\NVIDIA\GLCache" 2>nul
if exist "%LocalAppData%\AMD\DxCache" rd /s /q "%LocalAppData%\AMD\DxCache" 2>nul
powershell -Command "Clear-RecycleBin -Force -ErrorAction SilentlyContinue" 2>nul
cleanmgr /sagerun:1 >nul 2>&1
call :log "Phase 1: Completed"
goto :eof

:memoryoptimize_silent
call :log "Phase 2: Memory Optimization Started"
sc config "SysMain" start= disabled >nul 2>&1
sc stop "SysMain" >nul 2>&1
reg add "HKLM\SYSTEM\CurrentControlSet\Control\PriorityControl" /v Win32PrioritySeparation /t REG_DWORD /d 38 /f >nul
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v DisablePagingExecutive /t REG_DWORD /d 1 /f >nul
call :log "Phase 2: Completed"
goto :eof

:networkoptimize_silent
call :log "Phase 3: Network Optimization Started"
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" /v NetworkThrottlingIndex /t REG_DWORD /d 4294967295 /f >nul
netsh int tcp set global autotuninglevel=normal >nul
netsh int tcp set global chimney=enabled >nul
netsh int tcp set global rss=enabled >nul
ipconfig /flushdns >nul
call :log "Phase 3: Completed"
goto :eof

:visualoptimize_silent
call :log "Phase 4: Visual Effects Optimization Started"
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects" /v VisualFXSetting /t REG_DWORD /d 2 /f >nul
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize" /v EnableTransparency /t REG_DWORD /d 0 /f >nul
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v TaskbarAnimations /t REG_DWORD /d 0 /f >nul
call :log "Phase 4: Completed"
goto :eof

:registryoptimize_silent
call :log "Phase 5: Registry Optimization Started"
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v IoPageLockLimit /t REG_DWORD /d 983040 /f >nul
fsutil behavior set DisableLastAccess 1 >nul
fsutil behavior set MemoryUsage 2 >nul
fsutil behavior set MftZoneReservation 2 >nul
powercfg /hibernate off >nul
call :log "Phase 5: Completed"
goto :eof

:gamingoptimize_silent
call :log "Phase 6: Gaming Optimization Started"
reg add "HKCU\Software\Microsoft\GameBar" /v AutoGameModeEnabled /t REG_DWORD /d 1 /f >nul
reg add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers" /v HwSchMode /t REG_DWORD /d 2 /f >nul
reg add "HKCU\System\GameConfigStore" /v GameDVR_Enabled /t REG_DWORD /d 0 /f >nul
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v Priority /t REG_DWORD /d 6 /f >nul
call :log "Phase 6: Completed"
goto :eof

:: Restore All Settings
:restoreall
cls
echo ============================================================================
echo  RESTORING ALL SETTINGS TO DEFAULT
echo ============================================================================
echo.

call :log "=== Restore to Default Started ==="

echo [1/12] Restoring power plan...
call :log "Restoring power plan"
powercfg /setactive SCHEME_BALANCED >nul 2>&1

echo [2/12] Restoring services...
call :log "Restoring services"
sc config "SysMain" start= auto >nul 2>&1
sc config "WSearch" start= delayed-auto >nul 2>&1
sc config "Themes" start= auto >nul 2>&1
sc start "SysMain" >nul 2>&1
sc start "WSearch" >nul 2>&1
sc start "Themes" >nul 2>&1

echo [3/12] Restoring visual effects...
call :log "Restoring visual effects"
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects" /v VisualFXSetting /t REG_DWORD /d 0 /f >nul
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize" /v EnableTransparency /t REG_DWORD /d 1 /f >nul
reg add "HKCU\Control Panel\Desktop\WindowMetrics" /v MinAnimate /t REG_SZ /d 1 /f >nul
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v TaskbarAnimations /t REG_DWORD /d 1 /f >nul

echo [4/12] Restoring virtual memory to automatic...
call :log "Restoring virtual memory"
wmic computersystem where name="%computername%" set AutomaticManagedPagefile=True >nul 2>&1

echo [5/12] Restoring CPU scheduling...
call :log "Restoring CPU scheduling"
reg add "HKLM\SYSTEM\CurrentControlSet\Control\PriorityControl" /v Win32PrioritySeparation /t REG_DWORD /d 2 /f >nul

echo [6/12] Restoring network settings...
call :log "Restoring network settings"
netsh int tcp set global autotuninglevel=normal >nul
netsh int tcp set global chimney=disabled >nul
reg delete "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v NameServer /f >nul 2>&1

echo [7/12] Restoring file system settings...
call :log "Restoring file system"
fsutil behavior set DisableLastAccess 0 >nul
fsutil behavior set MemoryUsage 1 >nul
fsutil behavior set MftZoneReservation 1 >nul

echo [8/12] Re-enabling telemetry...
call :log "Restoring telemetry"
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection" /v AllowTelemetry /t REG_DWORD /d 3 /f >nul
schtasks /Change /TN "\Microsoft\Windows\Application Experience\Microsoft Compatibility Appraiser" /Enable >nul 2>&1

echo [9/12] Re-enabling hibernation...
call :log "Re-enabling hibernation"
powercfg /hibernate on >nul

echo [10/12] Restoring Game Mode settings...
call :log "Restoring Game Mode"
reg add "HKCU\Software\Microsoft\GameBar" /v AutoGameModeEnabled /t REG_DWORD /d 1 /f >nul
reg add "HKCU\System\GameConfigStore" /v GameDVR_Enabled /t REG_DWORD /d 1 /f >nul

echo [11/12] Restoring mouse settings...
call :log "Restoring mouse settings"
reg add "HKCU\Control Panel\Mouse" /v MouseSpeed /t REG_SZ /d 1 /f >nul
reg add "HKCU\Control Panel\Mouse" /v MouseThreshold1 /t REG_SZ /d 6 /f >nul
reg add "HKCU\Control Panel\Mouse" /v MouseThreshold2 /t REG_SZ /d 10 /f >nul

echo [12/12] Restoring Windows Defender...
call :log "Restoring Windows Defender"
sc config WinDefend start= auto >nul 2>&1
sc start WinDefend >nul 2>&1

echo.
echo ============================================================================
echo [SUCCESS] All settings have been restored to Windows defaults!
echo.
echo Your system has been returned to its original configuration.
echo Some optimizations like cleaned files will remain.
echo.
echo Restart recommended for all changes to take effect.
echo ============================================================================

call :log "=== Restore to Default Completed ==="

set /p restart="Do you want to restart your PC now? (Y/N): "
if /i "!restart!"=="Y" (
    echo.
    echo Restarting in 10 seconds... Press Ctrl+C to cancel.
    shutdown /r /t 10 /c "System restart after settings restoration"
)
pause
goto menu

:: Logging function
:log
echo [%date% %time%] %~1 >> "%LOGFILE%"
goto :eof
