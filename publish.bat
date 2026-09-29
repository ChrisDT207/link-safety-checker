@echo off
setlocal enabledelayedexpansion

echo ========================================================
echo 1/2 Building React Frontend Client...
echo ========================================================
cd client
call npm.cmd run build
if errorlevel 1 (
    echo [ERROR] React build failed.
    cd ..
    pause
    exit /b 1
)
cd ..

echo.
echo ========================================================
echo 2/2 Publishing Link Safety Checker Single-File Executable...
echo ========================================================
dotnet publish LinkSafetyChecker.csproj -c Release -r win-x64 --self-contained true -p:PublishSingleFile=true -o publish
if errorlevel 1 (
    echo [ERROR] Dotnet publish failed.
    pause
    exit /b 1
)

copy /y "publish\LinkSafetyChecker.exe" "LinkSafetyChecker.exe" >nul
if exist "C:\Users\chris\OneDrive\Desktop" (
    copy /y "publish\LinkSafetyChecker.exe" "C:\Users\chris\OneDrive\Desktop\LinkSafetyChecker.exe" >nul
    echo [OK] Copied executable to Desktop: C:\Users\chris\OneDrive\Desktop\LinkSafetyChecker.exe
)

echo.
echo ========================================================
echo Build Succeeded!
echo Single-file executable ready at:
echo   - publish\LinkSafetyChecker.exe
echo   - LinkSafetyChecker.exe (Project Root)
echo   - C:\Users\chris\OneDrive\Desktop\LinkSafetyChecker.exe (Desktop)
echo ========================================================


