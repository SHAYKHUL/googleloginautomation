"""
Runtime hook to suppress console windows and prevent terminal flickering
"""
import sys
import os

# Set UTF-8 encoding for all output to prevent Unicode errors
if hasattr(sys, 'stdout') and sys.stdout:
    try:
        sys.stdout.reconfigure(encoding='utf-8', errors='replace')
        sys.stderr.reconfigure(encoding='utf-8', errors='replace')
    except:
        pass

# Suppress all console output during startup
if hasattr(sys, '_MEIPASS'):
    # Running as PyInstaller bundle
    import ctypes
    from ctypes import wintypes
    
    # Hide console window completely
    kernel32 = ctypes.WinDLL('kernel32', use_last_error=True)
    user32 = ctypes.WinDLL('user32', use_last_error=True)
    
    # Get console window handle
    console_window = kernel32.GetConsoleWindow()
    if console_window:
        # Hide the console window
        user32.ShowWindow(console_window, 0)  # SW_HIDE = 0
        
    # Redirect stdout and stderr to null to prevent encoding issues
    try:
        sys.stdout = open(os.devnull, 'w', encoding='utf-8', errors='replace')
        sys.stderr = open(os.devnull, 'w', encoding='utf-8', errors='replace')
    except:
        pass
        
    # Suppress subprocess console windows
    import subprocess
    subprocess.CREATE_NO_WINDOW = 0x08000000
    
    # Override Popen to always use CREATE_NO_WINDOW
    original_popen_init = subprocess.Popen.__init__
    
    def patched_popen_init(self, *args, **kwargs):
        kwargs.setdefault('creationflags', 0)
        kwargs['creationflags'] |= subprocess.CREATE_NO_WINDOW
        return original_popen_init(self, *args, **kwargs)
    
    subprocess.Popen.__init__ = patched_popen_init