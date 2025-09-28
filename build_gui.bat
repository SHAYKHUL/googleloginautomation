@echo off
echo ========================================
echo  Google Account Automation GUI Tool
echo  Building Standalone Executable
echo ========================================
echo.

REM Check if Python is available
python --version >nul 2>&1
if %errorlevel% neq 0 (
    echo ❌ Python not found! Please install Python first.
    pause
    exit /b 1
)
echo ✅ Python found
echo.

REM Install required packages
echo 🔧 Installing required packages...
python -m pip install --upgrade pip pyinstaller selenium pycryptodome requests

REM Create executable directory
if not exist "gui_executable" mkdir gui_executable

echo.
echo 🔨 Building GUI executable...

REM Build the executable with PyInstaller
REM Make sure logo_icon.ico exists in the project directory
pyinstaller --onefile ^
    --icon "icon.ico" ^
    --noconsole ^
    --noupx ^
    --name "GoogleAccountAutomationGUI" ^
    --distpath "gui_executable" ^
    --workpath "gui_build" ^
    --add-data "*.py;." ^
    --runtime-hook "runtime_hook.py" ^
    --hidden-import "selenium.webdriver.chrome.service" ^
    --hidden-import "selenium.webdriver.chrome.options" ^
    --hidden-import "selenium.webdriver.common.by" ^
    --hidden-import "selenium.webdriver.common.keys" ^
    --hidden-import "selenium.webdriver.support.ui" ^
    --hidden-import "selenium.webdriver.support.expected_conditions" ^
    --hidden-import "selenium.common.exceptions" ^
    --hidden-import "tkinter" ^
    --hidden-import "tkinter.ttk" ^
    --hidden-import "tkinter.filedialog" ^
    --hidden-import "tkinter.messagebox" ^
    --hidden-import "tkinter.scrolledtext" ^
    --hidden-import "threading" ^
    --hidden-import "queue" ^
    --hidden-import "os" ^
    --hidden-import "sys" ^
    --hidden-import "time" ^
    --hidden-import "csv" ^
    --hidden-import "json" ^
    --hidden-import "hashlib" ^
    --hidden-import "platform" ^
    --hidden-import "subprocess" ^
    --hidden-import "ctypes" ^
    --hidden-import "ctypes.wintypes" ^
    --collect-all "selenium" ^
    gui_automation.py

if %errorlevel% equ 0 (
    echo.
    echo ✅ Build complete! The results are available in: %CD%\gui_executable
    echo 📁 File created: GoogleAccountAutomationGUI.exe
    echo.
    echo 📋 To use:
    echo   1. Copy GoogleAccountAutomationGUI.exe to any Windows computer
    echo   2. Prepare your accounts.csv file
    echo   3. Run the GUI and select your CSV file
    echo   4. Click Start Automation
    echo.
) else (
    echo ❌ Build failed! Check the error messages above.
)

pause