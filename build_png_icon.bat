@echo off
echo ========================================
echo  Direct PNG Icon Build
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

REM Check if icon.png exists
if not exist "icon.png" (
    echo ❌ icon.png not found! Please ensure icon.png is in the project directory.
    pause
    exit /b 1
)

REM Show icon.png info
for %%F in ("icon.png") do (
    echo ✅ Found icon.png: %%~zF bytes
)

REM Install required packages
echo 🔧 Installing required packages...
python -m pip install --upgrade pip pyinstaller selenium pycryptodome requests

REM Create executable directory
if not exist "gui_executable" mkdir gui_executable

REM Clean previous builds
echo 🧹 Cleaning previous builds...
if exist "gui_build" rmdir /s /q gui_build
if exist "dist" rmdir /s /q dist
if exist "build" rmdir /s /q build

echo.
echo 🔨 Building with icon.png directly...

REM Build directly with PNG - PyInstaller will auto-convert
pyinstaller ^
    --onefile ^
    --windowed ^
    --icon="icon.png" ^
    --name="GoogleAccountAutomationGUI" ^
    --distpath="gui_executable" ^
    --workpath="gui_build" ^
    --add-data="*.py;." ^
    --add-data="icon.png;." ^
    --runtime-hook="runtime_hook.py" ^
    --hidden-import="selenium.webdriver.chrome.service" ^
    --hidden-import="selenium.webdriver.chrome.options" ^
    --hidden-import="tkinter" ^
    --hidden-import="tkinter.ttk" ^
    --hidden-import="tkinter.filedialog" ^
    --hidden-import="tkinter.messagebox" ^
    --hidden-import="threading" ^
    --hidden-import="queue" ^
    --collect-all="selenium" ^
    --log-level="INFO" ^
    gui_automation.py

if %errorlevel% equ 0 (
    echo.
    echo ✅ Build complete using icon.png!
    echo 📁 Executable: gui_executable\GoogleAccountAutomationGUI.exe
    
    if exist "gui_executable\GoogleAccountAutomationGUI.exe" (
        for %%F in ("gui_executable\GoogleAccountAutomationGUI.exe") do (
            echo 📊 Size: %%~zF bytes
        )
        
        echo.
        echo 🚀 Testing launch...
        start "" "gui_executable\GoogleAccountAutomationGUI.exe"
        echo ✅ Launched! Check taskbar for your PNG icon!
        
    ) else (
        echo ❌ Executable not found!
    )
) else (
    echo ❌ Build failed!
)

echo.
echo 💡 PyInstaller automatically converts PNG to ICO format
echo    Your icon.png should now appear in the executable!
echo.
pause