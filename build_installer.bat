@echo off
REM ================================================================
REM Advanced Installer Builder for Google Account Automation Tool
REM ================================================================

setlocal EnableDelayedExpansion

echo.
echo ================================================================
echo  Advanced Installer Builder
echo  Google Account Automation Tool v1.0.0
echo ================================================================
echo.

REM Check if Inno Setup is installed
set "INNO_PATH="
if exist "C:\Program Files (x86)\Inno Setup 6\ISCC.exe" (
    set "INNO_PATH=C:\Program Files (x86)\Inno Setup 6\ISCC.exe"
) else if exist "C:\Program Files\Inno Setup 6\ISCC.exe" (
    set "INNO_PATH=C:\Program Files\Inno Setup 6\ISCC.exe"
) else (
    echo ❌ Error: Inno Setup 6 not found!
    echo.
    echo Please download and install Inno Setup from:
    echo https://jrsoftware.org/isinfo.php
    echo.
    echo Install to default location and try again.
    pause
    exit /b 1
)

echo ✅ Found Inno Setup at: !INNO_PATH!
echo.

REM Create necessary directories
echo 📁 Creating installer directories...
if not exist "installer_output" mkdir "installer_output"
if not exist "installer_assets" mkdir "installer_assets"

REM Check if main executable exists
if not exist "gui_executable\GoogleAccountAutomationGUI.exe" (
    echo ❌ Error: Main executable not found!
    echo Expected: gui_executable\GoogleAccountAutomationGUI.exe
    echo.
    echo Please build the application first using build_gui.bat
    pause
    exit /b 1
)

.\build_installer.batecho ✅ Main executable found
echo.

REM Create simple icons if they don't exist (optional)
echo 🎨 Setting up installer assets...

REM Create a basic license file if it doesn't exist
if not exist "LICENSE" (
    echo Creating LICENSE file...
    (
        echo.
        echo LICENSE AGREEMENT
        echo =================
        echo.
        echo Google Account Automation Tool
        echo Copyright ^(c^) 2025 Algolizen Solutions
        echo.
        echo This software is licensed for use with a valid license key.
        echo Unauthorized use, distribution, or modification is prohibited.
        echo.
        echo For licensing information, visit: https://algolizen.com
        echo.
    ) > LICENSE
)

REM Create README if it doesn't exist
if not exist "README.md" (
    echo Creating README.md...
    (
        echo # Google Account Automation Tool
        echo.
        echo Professional automation software for Google Account 2FA setup.
        echo.
        echo ## Features
        echo - Automated Google Account login and 2FA setup
        echo - Enterprise-grade security with license validation
        echo - Comprehensive error detection and verification handling
        echo - Professional GUI interface with progress tracking
        echo.
        echo ## System Requirements
        echo - Windows 7 SP1 or later ^(64-bit^)
        echo - Valid license key required
        echo - Internet connection for license validation
        echo.
        echo ## Installation
        echo Run the installer and follow the setup wizard instructions.
        echo.
        echo ## Usage
        echo 1. Launch the application
        echo 2. Enter your license key
        echo 3. Load your accounts CSV file
        echo 4. Start automation process
        echo.
        echo ## Support
        echo For support and licensing: https://algolizen.com
        echo.
    ) > README.md
)

echo ✅ Installer assets ready
echo.

REM Compile the installer
echo 🔨 Compiling installer...
echo Running Inno Setup Compiler...
echo.

"!INNO_PATH!" "GoogleAccountAutomationToolInstaller.iss"

if %errorlevel% equ 0 (
    echo.
    echo ================================================================
    echo ✅ SUCCESS: Advanced installer created successfully!
    echo ================================================================
    echo.
    echo 📁 Output location: installer_output\
    echo 📦 Installer file: GoogleAccountAutomationTool_v1.0.0_Setup.exe
    echo.
    echo 🎯 Features included:
    echo   • Modern wizard-style interface
    echo   • Component-based installation
    echo   • Multi-language support
    echo   • Desktop and Start Menu shortcuts
    echo   • File associations for CSV files
    echo   • Professional uninstaller
    echo   • System requirements checking
    echo   • Registry integration
    echo   • Automatic cleanup on uninstall
    echo.
    echo 🚀 The installer is ready for distribution!
    echo.
    
    REM Show file size
    for %%F in ("installer_output\GoogleAccountAutomationTool_v1.0.0_Setup.exe") do (
        set "size=%%~zF"
        set /a "sizeMB=!size!/1048576"
        echo 📊 Installer size: !sizeMB! MB
    )
    
    echo.
    echo Would you like to test the installer now? ^(Y/N^)
    set /p "choice=Choice: "
    if /i "!choice!"=="Y" (
        echo.
        echo 🧪 Launching test installer...
        start "" "installer_output\GoogleAccountAutomationTool_v1.0.0_Setup.exe"
    )
    
) else (
    echo.
    echo ❌ ERROR: Installer compilation failed!
    echo.
    echo Check the Inno Setup compiler output above for errors.
    echo Common issues:
    echo   • Missing source files
    echo   • Incorrect file paths in the script
    echo   • Inno Setup syntax errors
    echo.
)

echo.
pause