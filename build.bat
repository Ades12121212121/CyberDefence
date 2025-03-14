@echo off
cls
color 0A

echo ===============================================
echo        CyberDefence Builder - v1.0
echo ===============================================
echo.

:: Check if Python is installed
python --version >nul 2>&1
if errorlevel 1 (
    color 0C
    echo [ERROR] Python is not installed or not in PATH
    echo Please install Python and try again
    pause
    exit /b 1
)

:: Check if executable already exists
if exist "dist\CyberDefence.exe" (
    echo [*] CyberDefence.exe already exists
    echo [*] Checking/Installing requirements...
    pip install -r requirements.txt
    if errorlevel 1 (
        color 0C
        echo [ERROR] Failed to install requirements
        pause
        exit /b 1
    )
    echo.
    echo [+] Requirements installed successfully
    echo [*] Starting CyberDefence.exe...
    echo.
    start "" "dist\CyberDefence.exe"
    exit /b 0
)

:: If no executable exists, proceed with build process
echo [*] Creating build directories...
if not exist "dist" mkdir dist
if not exist "build" mkdir build

:: Install requirements
echo [*] Installing requirements...
pip install -r requirements.txt
if errorlevel 1 (
    color 0C
    echo [ERROR] Failed to install requirements
    pause
    exit /b 1
)

:: Build process
echo.
echo [*] Starting build process...
echo [*] This may take several minutes...
echo.

python build.py
if errorlevel 1 (
    color 0C
    echo.
    echo [ERROR] Build failed!
    echo Check the error messages above for more details
    pause
    exit /b 1
)

:: Verify build
if not exist "dist\CyberDefence.exe" (
    color 0C
    echo.
    echo [ERROR] Build failed - Executable not found
    pause
    exit /b 1
)

:: Success message
color 0A
echo.
echo ===============================================
echo              Build Successful!
echo ===============================================
echo.
echo [+] Executable created: dist\CyberDefence.exe
echo [+] Build completed successfully
echo.
echo Starting CyberDefence.exe...
echo.

:: Start the program
start "" "dist\CyberDefence.exe"

:end
echo.
echo Press any key to exit...
pause >nul