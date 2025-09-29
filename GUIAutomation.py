#!/usr/bin/env python3
"""
Google Account 2FA Setup Automation Tool with Licensed System
Suppress all console windows and terminal flickering
"""

# ==================== CONSOLE SUPPRESSION ====================
# Must be at the very top to prevent any console windows
import sys
import os

# Safe print function to handle Unicode encoding errors
def safe_print(*args, **kwargs):
    """Print function that handles Unicode encoding errors safely"""
    try:
        print(*args, **kwargs)
    except UnicodeEncodeError:
        # Convert any Unicode characters to ASCII equivalents
        safe_args = []
        for arg in args:
            if isinstance(arg, str):
                # Replace common Unicode characters with ASCII equivalents
                safe_arg = (arg.replace('🔍', '[CHECK]')
                           .replace('✅', '[OK]')
                           .replace('❌', '[ERROR]')
                           .replace('⚠️', '[WARNING]')
                           .replace('🚀', '[START]')
                           .replace('🛡️', '[SECURITY]')
                           .replace('🎯', '[TARGET]')
                           .replace('📁', '[FILE]'))
                safe_args.append(safe_arg)
            else:
                safe_args.append(str(arg))
        try:
            print(*safe_args, **kwargs)
        except:
            # Last resort: print without any special characters
            print("Application starting...")

# Set encoding for output streams if available
try:
    if hasattr(sys.stdout, 'reconfigure'):
        sys.stdout.reconfigure(encoding='utf-8', errors='replace')
    if hasattr(sys.stderr, 'reconfigure'):
        sys.stderr.reconfigure(encoding='utf-8', errors='replace')
except:
    pass

# Immediately suppress console for PyInstaller bundle
if getattr(sys, 'frozen', False):
    try:
        import ctypes
        from ctypes import wintypes
        
        # Get handles for console manipulation
        kernel32 = ctypes.WinDLL('kernel32', use_last_error=True)
        user32 = ctypes.WinDLL('user32', use_last_error=True)
        
        # Find and hide console window
        console_window = kernel32.GetConsoleWindow()
        if console_window:
            user32.ShowWindow(console_window, 0)  # SW_HIDE
            
        # Redirect output to suppress any residual console output
        try:
            sys.stdout = open(os.devnull, 'w', encoding='utf-8', errors='replace')
            sys.stderr = open(os.devnull, 'w', encoding='utf-8', errors='replace')
        except:
            pass
    except:
        pass

import tkinter as tk
from tkinter import ttk, filedialog, messagebox, scrolledtext
import csv
import time
import os
import sys
import threading
import queue
import tempfile
import shutil
import atexit
from datetime import datetime
from selenium import webdriver
# License system imports
import hashlib
import uuid
import platform
import hmac
import requests
import subprocess
from base64 import b64encode, b64decode
try:
    from Crypto.Cipher import AES
    from Crypto.Util.Padding import pad, unpad
except ImportError as e:
    safe_print("License system requires pycryptodome. Install with: pip install pycryptodome")
    safe_print(f"Import error: {e}")
    sys.exit(1)
import logging
from selenium.webdriver.common.by import By
from selenium.webdriver.common.keys import Keys
from selenium.webdriver.chrome.service import Service
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium.common.exceptions import TimeoutException, NoSuchElementException, ElementNotInteractableException, InvalidSessionIdException, WebDriverException
from selenium.webdriver.common.action_chains import ActionChains
import random
import json
from urllib.parse import urlparse

# ======================== LICENSE SYSTEM CONSTANTS ========================
# ⚠️ IMPORTANT: Configure these settings before deployment
LICENSE_SERVER_URL = "https://algolizen.com/activationserver"  # Change to your server URL
ACTIVATION_ENDPOINT = f"{LICENSE_SERVER_URL}/activate"  # Correct activation endpoint
VALIDATION_ENDPOINT = f"{LICENSE_SERVER_URL}/activate"  # Use same endpoint for validation

# ⚠️ SECURITY CRITICAL: Replace with your actual 32-byte secret key (base64 encoded recommended)
SECRET_KEY = "a1b2c3d4e5f67890abcdef1234567890abcdef1234567890abcdef1234567890"  # Must be exactly 32 bytes (64 hex chars)
HMAC_KEY = "fedcba0987654321fedcba0987654321fedcba0987654321fedcba0987654321"    # Must be exactly 32 bytes (64 hex chars)

# Security configuration flags - DO NOT DISABLE IN PRODUCTION
LICENSE_ENFORCEMENT_ACTIVE = True  # Master license enforcement flag
ANTI_DEBUG_ACTIVE = True          # Anti-debugging protection
INTEGRITY_CHECK_ACTIVE = True     # Application integrity verification
RUNTIME_VALIDATION_ACTIVE = True  # Runtime license validation

# ======================== IMMEDIATE EXPIRY ENFORCEMENT ========================
def _immediate_expiry_shutdown(expiry_date):
    """Immediate application termination when license expires - NO RECOVERY POSSIBLE"""
    safe_print("=" * 80)
    safe_print("[CRITICAL] LICENSE HAS EXPIRED!")
    safe_print(f"[ERROR] Expiry Date: {expiry_date}")
    safe_print(f"[ERROR] Current Date: {datetime.now().strftime('%Y-%m-%d')}")
    safe_print("[ERROR] APPLICATION TERMINATING IMMEDIATELY")
    safe_print("[ERROR] RENEW YOUR LICENSE TO CONTINUE USING THIS SOFTWARE")
    safe_print("=" * 80)
    
    # Show error dialog if GUI is available
    try:
        import tkinter.messagebox as msgbox
        msgbox.showerror(
            "LICENSE EXPIRED", 
            f"Your license expired on {expiry_date}.\n\n"
            f"The application will now terminate.\n\n"
            f"Please contact support to renew your license."
        )
    except:
        pass
    
    # Force immediate termination - NO RECOVERY POSSIBLE
    os._exit(1)

def _check_license_expiry_immediate():
    """Check license expiry and terminate immediately if expired"""
    try:
        license_file = "license.dat"
        if os.path.exists(license_file):
            with open(license_file, 'r') as f:
                encrypted_data = f.read().strip()
            if encrypted_data:
                decrypted = decrypt_license(encrypted_data)
                if decrypted:
                    license_info = json.loads(decrypted)
                    if 'expiry' in license_info:
                        try:
                            expiry_date = datetime.strptime(license_info['expiry'], '%Y-%m-%d')
                            if datetime.now() > expiry_date:
                                _immediate_expiry_shutdown(license_info['expiry'])
                        except Exception:
                            _immediate_expiry_shutdown("INVALID_DATE")
    except Exception:
        # If we can't read license, assume it's invalid/expired
        _immediate_expiry_shutdown("UNREADABLE_LICENSE")

# Example of proper key generation (run once, then use the generated keys):
# import os
# import base64
# SECRET_KEY = base64.b64encode(os.urandom(32))
# HMAC_KEY = base64.b64encode(os.urandom(32))
# print(f"SECRET_KEY = {SECRET_KEY}")
# print(f"HMAC_KEY = {HMAC_KEY}")

# ======================== LICENSE SYSTEM FUNCTIONS ========================
def get_hardware_id():
    """Generate a unique hardware identifier based on multiple system characteristics"""
    try:
        # Get MAC address (most stable)
        mac = uuid.getnode()
        mac_hex = f"{mac:012x}"
        
        # Get processor info
        try:
            if platform.system() == "Windows":
                result = subprocess.run(['wmic', 'cpu', 'get', 'ProcessorId', '/format:list'], 
                                      capture_output=True, text=True, timeout=10)
                processor_id = ""
                for line in result.stdout.split('\n'):
                    if 'ProcessorId=' in line:
                        processor_id = line.split('=')[1].strip()
                        break
            else:
                processor_id = platform.processor()
        except:
            processor_id = platform.machine()
        
        # Get disk serial (when available)
        disk_serial = ""
        try:
            if platform.system() == "Windows":
                result = subprocess.run(['wmic', 'diskdrive', 'get', 'SerialNumber', '/format:list'], 
                                      capture_output=True, text=True, timeout=10)
                for line in result.stdout.split('\n'):
                    if 'SerialNumber=' in line and line.split('=')[1].strip():
                        disk_serial = line.split('=')[1].strip()
                        break
        except:
            pass
        
        # Combine all identifiers
        hardware_string = f"{mac_hex}_{processor_id}_{disk_serial}_{platform.system()}"
        
        # Create SHA-256 hash
        hardware_hash = hashlib.sha256(hardware_string.encode()).hexdigest()
        
        return hardware_hash[:24]  # Return first 24 characters for readability
        
    except Exception as e:
        print(f"Error generating hardware ID: {e}")
        # Fallback to MAC address only
        mac = uuid.getnode()
        return hashlib.sha256(f"{mac:012x}".encode()).hexdigest()[:24]

def encrypt_license(license_data):
    """Encrypt license data using AES"""
    try:
        # Convert hex string to bytes for AES
        key_bytes = bytes.fromhex(SECRET_KEY)
        cipher = AES.new(key_bytes, AES.MODE_CBC)
        padded_data = pad(license_data.encode(), AES.block_size)
        encrypted = cipher.encrypt(padded_data)
        return b64encode(cipher.iv + encrypted).decode()
    except Exception as e:
        print(f"Encryption error: {e}")
        return None

def decrypt_license(encrypted_license):
    """Decrypt license data"""
    try:
        # Convert hex string to bytes for AES
        key_bytes = bytes.fromhex(SECRET_KEY)
        encrypted_data = b64decode(encrypted_license.encode())
        iv = encrypted_data[:16]
        ciphertext = encrypted_data[16:]
        cipher = AES.new(key_bytes, AES.MODE_CBC, iv)
        decrypted = unpad(cipher.decrypt(ciphertext), AES.block_size)
        return decrypted.decode()
    except Exception as e:
        print(f"Decryption error: {e}")
        return None

def generate_signature(data, key=HMAC_KEY):
    """Generate HMAC signature for data integrity"""
    return hmac.new(key, data.encode(), hashlib.sha256).hexdigest()

def verify_signature(data, signature, key=HMAC_KEY):
    """Verify HMAC signature"""
    expected = generate_signature(data, key)
    return hmac.compare_digest(expected, signature)

def validate_license_key(license_key, hardware_id):
    """Validate license key against hardware ID and server"""
    try:
        # First check if license file exists
        license_file = "license.dat"
        if os.path.exists(license_file):
            with open(license_file, 'r') as f:
                stored_data = f.read().strip()
                if stored_data:
                    decrypted = decrypt_license(stored_data)
                    if decrypted:
                        license_info = json.loads(decrypted)
                        if license_info.get('hardware_id') == hardware_id:
                            # CRITICAL: Check expiry date for local validation
                            if 'expiry' in license_info:
                                try:
                                    expiry_date = datetime.strptime(license_info['expiry'], '%Y-%m-%d')
                                    if datetime.now() > expiry_date:
                                        return False, f"License expired on {license_info['expiry']}"
                                except Exception as e:
                                    return False, f"Invalid expiry date format: {e}"
                            return True, "License validated from local storage"
        
        # Skip online validation if no license key provided (initial check)
        if not license_key:
            return False, "No license key provided for validation"
        
        # Online validation - match server.js format
        payload = {
            'hardware_id': hardware_id,
            'license_key': license_key
        }
        
        print(f"[DEBUG] Validating license with server: {VALIDATION_ENDPOINT}")
        print(f"[DEBUG] Payload: {payload}")
        
        try:
            response = requests.post(VALIDATION_ENDPOINT, json=payload, timeout=10)
            print(f"[DEBUG] Server response status: {response.status_code}")
            print(f"[DEBUG] Server response headers: {dict(response.headers)}")
            print(f"[DEBUG] Server response text: {response.text}")
            
            if response.status_code == 200:
                result = response.json()
                if result.get('status') == 'ok':
                    # Save license locally
                    license_data = {
                        'license_key': license_key,
                        'hardware_id': hardware_id,
                        'validated': True,
                        'timestamp': int(time.time())
                    }
                    encrypted_license = encrypt_license(json.dumps(license_data))
                    if encrypted_license:
                        with open(license_file, 'w') as f:
                            f.write(encrypted_license)
                    return True, "License validated successfully"
                else:
                    return False, result.get('message', 'Invalid license key')
            else:
                error_msg = response.text if response.text else f"HTTP {response.status_code}"
                return False, f"Server error: {error_msg}"
        except requests.RequestException as e:
            print(f"[DEBUG] Network error: {e}")
            # Offline mode - check local license
            if os.path.exists(license_file):
                return True, "Using cached license (offline mode)"
            return False, f"No internet connection and no cached license found. Network error: {e}"
            
    except Exception as e:
        print(f"[DEBUG] License validation error: {e}")
        return False, f"License validation error: {e}"

def activate_license(license_key, hardware_id):
    """Activate license key with the server"""
    try:
        # Match server.js expected format
        payload = {
            'hardware_id': hardware_id,
            'license_key': license_key
        }
        
        print(f"[DEBUG] Activating license with server: {ACTIVATION_ENDPOINT}")
        print(f"[DEBUG] Payload: {payload}")
        
        response = requests.post(ACTIVATION_ENDPOINT, json=payload, timeout=10)
        
        print(f"[DEBUG] Activation response status: {response.status_code}")
        print(f"[DEBUG] Activation response headers: {dict(response.headers)}")
        print(f"[DEBUG] Activation response text: {response.text}")
        
        if response.status_code == 200:
            result = response.json()
            if result.get('status') == 'ok':
                # Save license locally with expiry extracted from license key
                try:
                    # Extract expiry date from license key format: CALC-{hardware}-{expiry}-{sig}
                    parts = license_key.split('-')
                    if len(parts) >= 3:
                        expiry_str = parts[2]  # Format: YYYYMMDD
                        expiry_formatted = f"{expiry_str[:4]}-{expiry_str[4:6]}-{expiry_str[6:8]}"  # Format: YYYY-MM-DD
                        
                        license_data = {
                            'license_key': license_key,
                            'hardware_id': hardware_id,
                            'validated': True,  # Changed from 'activated' to 'validated' to match validation function
                            'expiry': expiry_formatted,
                            'activation_date': datetime.now().strftime('%Y-%m-%d'),
                            'timestamp': int(time.time()),
                            'version': '3.0'
                        }
                    else:
                        # Fallback if license key format is unexpected
                        license_data = {
                            'license_key': license_key,
                            'hardware_id': hardware_id,
                            'validated': True,
                            'activation_date': datetime.now().strftime('%Y-%m-%d'),
                            'timestamp': int(time.time()),
                            'version': '3.0'
                        }
                except Exception as e:
                    print(f"Error parsing license key: {e}")
                    license_data = {
                        'license_key': license_key,
                        'hardware_id': hardware_id,
                        'validated': True,
                        'activation_date': datetime.now().strftime('%Y-%m-%d'),
                        'timestamp': int(time.time()),
                        'version': '3.0'
                    }
                
                encrypted_license = encrypt_license(json.dumps(license_data))
                if encrypted_license:
                    with open("license.dat", 'w') as f:
                        f.write(encrypted_license)
                return True, result.get('message', 'License activated successfully')
            else:
                return False, result.get('message', 'Activation failed')
        else:
            error_msg = response.text if response.text else f"HTTP {response.status_code}"
            return False, f"Server error: {error_msg}"
            
    except requests.RequestException as e:
        print(f"[DEBUG] Network error during activation: {e}")
        return False, f"Network error during activation: {e}"
    except Exception as e:
        print(f"[DEBUG] Activation error: {e}")
        return False, f"Activation error: {e}"

def show_license_window(parent_root):
    """Show license activation window"""
    license_window = tk.Toplevel(parent_root)
    license_window.title("License Activation Required")
    license_window.resizable(False, False)
    
    # Calculate center position BEFORE showing the window
    window_width = 500
    window_height = 400
    screen_width = license_window.winfo_screenwidth()
    screen_height = license_window.winfo_screenheight()
    x = (screen_width - window_width) // 2
    y = (screen_height - window_height) // 2
    
    # Set geometry with position immediately
    license_window.geometry(f"{window_width}x{window_height}+{x}+{y}")
    license_window.grab_set()
    
    # Ensure window is focused and on top
    license_window.focus_force()
    license_window.lift()
    license_window.attributes('-topmost', True)
    license_window.after(100, lambda: license_window.attributes('-topmost', False))
    
    main_frame = ttk.Frame(license_window, padding="20")
    main_frame.pack(fill='both', expand=True)
    
    # Title
    title_label = ttk.Label(main_frame, text="License Activation", 
                           font=('Arial', 16, 'bold'))
    title_label.pack(pady=(0, 20))
    
    # Hardware ID display
    hardware_id = get_hardware_id()
    ttk.Label(main_frame, text="Your Hardware ID:", 
             font=('Arial', 10, 'bold')).pack(anchor='w')
    
    hw_frame = ttk.Frame(main_frame)
    hw_frame.pack(fill='x', pady=(5, 15))
    
    hw_entry = ttk.Entry(hw_frame, font=('Courier', 10))
    hw_entry.insert(0, hardware_id)
    hw_entry.config(state='readonly')
    hw_entry.pack(side='left', fill='x', expand=True)
    
    def copy_hardware_id():
        license_window.clipboard_clear()
        license_window.clipboard_append(hardware_id)
        messagebox.showinfo("Copied", "Hardware ID copied to clipboard")
    
    ttk.Button(hw_frame, text="Copy", command=copy_hardware_id).pack(side='right', padx=(5, 0))
    
    # License key entry
    ttk.Label(main_frame, text="Enter your license key:", 
             font=('Arial', 10, 'bold')).pack(anchor='w', pady=(10, 5))
    
    license_entry = ttk.Entry(main_frame, font=('Arial', 12), width=50)
    license_entry.pack(fill='x', pady=(0, 15))
    license_entry.focus()
    
    # Status label
    status_label = ttk.Label(main_frame, text="", foreground='red')
    status_label.pack(pady=(0, 10))
    
    # Result variable
    activation_result = {'success': False}
    
    def activate():
        license_key = license_entry.get().strip()
        if not license_key:
            status_label.config(text="Please enter a license key", foreground='red')
            return
        
        status_label.config(text="Activating license...", foreground='blue')
        license_window.update()
        
        # Try activation first
        success, message = activate_license(license_key, hardware_id)
        
        if not success:
            # Try validation if activation fails
            success, message = validate_license_key(license_key, hardware_id)
        
        if success:
            status_label.config(text=message, foreground='green')
            activation_result['success'] = True
            license_window.after(1500, license_window.destroy)
        else:
            status_label.config(text=message, foreground='red')
    
    def on_enter(event):
        activate()
    
    def on_escape(event):
        safe_exit()
    
    license_entry.bind('<Return>', on_enter)
    license_window.bind('<Escape>', on_escape)  # Allow Escape key to exit
    
    # Buttons
    button_frame = ttk.Frame(main_frame)
    button_frame.pack(side='bottom', fill='x', pady=(20, 0))
    
    def safe_exit():
        """Safely exit the application"""
        try:
            license_window.destroy()
        except:
            pass
        try:
            parent_root.destroy()
        except:
            pass
        sys.exit(0)
    
    ttk.Button(button_frame, text="Activate", command=activate).pack(side='right')
    ttk.Button(button_frame, text="Exit", command=safe_exit).pack(side='right', padx=(0, 10))
    
    # Instructions
    instructions = ttk.Label(main_frame, 
                           text="Instructions:\n1. Copy your Hardware ID\n2. Contact support to get your license key\n3. Enter the license key and click Activate",
                           justify='left', foreground='gray')
    instructions.pack(side='bottom', anchor='w', pady=(10, 0))
    
    license_window.protocol("WM_DELETE_WINDOW", safe_exit)
    license_window.wait_window()
    
    return activation_result['success']

def periodic_license_check():
    """Periodically check license validity with multiple security layers"""
    def comprehensive_license_check():
        while True:
            try:
                # IMMEDIATE REVOCATION: Multiple validation layers every 30 seconds
                if not LICENSE_ENFORCEMENT_ACTIVE:
                    safe_print("🚨 SECURITY VIOLATION: License enforcement disabled during runtime!")
                    _emergency_shutdown("License enforcement disabled")
                
                # Primary license check with server validation
                hardware_id = get_hardware_id()
                valid, message = validate_license_key("", hardware_id)
                if not valid:
                    safe_print(f"🚨 SECURITY VIOLATION: License became invalid during runtime! {message}")
                    _emergency_shutdown(f"License invalid: {message}")
                
                # Secondary obfuscated checks
                if not _0x4c1c3ns3_ch3ck():
                    safe_print("🚨 SECURITY VIOLATION: Primary security check failed!")
                    _emergency_shutdown("Primary security check failed")
                    
                if not _0x5d2e4f1a_v4l1d4t3():
                    safe_print("🚨 SECURITY VIOLATION: Secondary security check failed!")
                    _emergency_shutdown("Secondary security check failed")
                    
                if not _0x7f3a9b2c_s3cur1ty():
                    safe_print("🚨 SECURITY VIOLATION: Tertiary security check failed!")
                    _emergency_shutdown("Tertiary security check failed")
                
                # Additional integrity verification
                _verify_app_integrity()
                
                # Check for license file tampering
                if not os.path.exists("license.dat"):
                    safe_print("🚨 SECURITY VIOLATION: License file deleted during runtime!")
                    _emergency_shutdown("License file deleted")
                
                # 🔒 ENHANCED SECURITY: Check for bypass attempts
                if os.path.exists("master_access.key") or os.path.exists("bypass.key") or os.path.exists("unlock.key"):
                    safe_print("🚨 SECURITY VIOLATION: Unauthorized bypass file detected!")
                    _emergency_shutdown("Bypass attempt detected")
                
                # Additional license integrity check
                if not _validate_license_integrity():
                    safe_print("🚨 SECURITY VIOLATION: License integrity compromised!")
                    _emergency_shutdown("License integrity failure")
                
                # Admin kill switch check
                if _check_admin_kill_switch():
                    safe_print("🚨 ADMIN TERMINATION: Application terminated by administrator")
                    _emergency_shutdown("Admin kill switch activated")
                
                time.sleep(30)  # Check every 30 seconds for immediate revocation detection
            except Exception as e:
                print(f"SECURITY VIOLATION: License check failed: {e}")
                os._exit(1)
    
    thread = threading.Thread(target=comprehensive_license_check, daemon=True)
    thread.start()

def _emergency_shutdown(reason):
    """Immediate emergency shutdown with cleanup when license is revoked"""
    try:
        safe_print(f"🛑 EMERGENCY SHUTDOWN: {reason}")
        safe_print("🔒 Access revoked by administrator. Contact support for assistance.")
        
        # Show GUI message box for user-friendly notification
        try:
            import tkinter as tk
            from tkinter import messagebox
            
            # Create a temporary root window (hidden)
            root = tk.Tk()
            root.withdraw()  # Hide the main window
            root.attributes('-topmost', True)  # Keep dialog on top
            
            # Show emergency shutdown dialog
            messagebox.showerror(
                "🚨 ACCESS REVOKED", 
                f"🛑 EMERGENCY SHUTDOWN\n\n"
                f"Reason: {reason}\n\n"
                f"🔒 Access has been revoked by the administrator.\n\n"
                f"Please contact support for assistance.\n\n"
                f"The application will now close."
            )
            
            root.destroy()
        except Exception as e:
            safe_print(f"Could not show GUI dialog: {e}")
        
        # Close any open browsers/webdrivers
        try:
            import psutil
            for proc in psutil.process_iter(['pid', 'name']):
                if proc.info['name'] in ['chrome.exe', 'chromedriver.exe', 'firefox.exe', 'geckodriver.exe']:
                    try:
                        proc.terminate()
                    except:
                        pass
        except:
            pass
        
        # Force immediate termination
        time.sleep(2)  # Give user time to see the message
        os._exit(1)
    except:
        os._exit(1)

def _check_admin_kill_switch():
    """Check server for admin kill switch command"""
    try:
        hardware_id = get_hardware_id()
        response = requests.get(
            f"{LICENSE_SERVER_URL}/kill-switch-status", 
            params={'hardware_id': hardware_id},
            timeout=5
        )
        if response.status_code == 200:
            result = response.json()
            return result.get('terminate', False)
    except:
        pass
    return False

# Multiple obfuscated license validation functions to prevent bypass
def _0x4c1c3ns3_ch3ck():
    """Primary obfuscated license check - DO NOT REMOVE"""
    try:
        if not LICENSE_ENFORCEMENT_ACTIVE:
            os._exit(1)
        
        hw_id = get_hardware_id()
        license_file = "license.dat"
        if not os.path.exists(license_file):
            return False
        with open(license_file, 'r') as f:
            encrypted_data = f.read().strip()
        if not encrypted_data:
            return False
        decrypted = decrypt_license(encrypted_data)
        if not decrypted:
            return False
        license_info = json.loads(decrypted)
        
        # Check hardware ID and validation status
        if not (license_info.get('hardware_id') == hw_id and license_info.get('validated', False)):
            return False
        
        # CRITICAL: Check expiry date
        if 'expiry' in license_info:
            try:
                expiry_date = datetime.strptime(license_info['expiry'], '%Y-%m-%d')
                if datetime.now() > expiry_date:
                    print(f"SECURITY VIOLATION: License expired on {license_info['expiry']}")
                    return False  # License has expired
            except Exception as e:
                print(f"SECURITY VIOLATION: Invalid expiry date format: {e}")
                return False
        
        result = True
        
        # Additional runtime check
        if result:
            _verify_app_integrity()
        
        return result
    except:
        return False

def _validate_license_integrity(license_info):
    """Additional license integrity validation"""
    try:
        # Check system integrity
        if not INTEGRITY_CHECK_ACTIVE:
            return False
        
        # Verify critical security flags
        security_checks = [
            LICENSE_ENFORCEMENT_ACTIVE,
            ANTI_DEBUG_ACTIVE, 
            INTEGRITY_CHECK_ACTIVE,
            RUNTIME_VALIDATION_ACTIVE
        ]
        
        if not all(security_checks):
            return False  # Don't exit here, let main validation handle it
        
        # Additional hardware verification
        current_hw = get_hardware_id()
        if not current_hw or len(current_hw) < 20:
            return False
        
        return True
    except:
        return False

def _0x5d2e4f1a_v4l1d4t3():
    """Secondary obfuscated license check - DO NOT REMOVE"""
    try:
        if not RUNTIME_VALIDATION_ACTIVE:
            return False
        
        # Check expiry before other validations
        license_file = "license.dat"
        if os.path.exists(license_file):
            with open(license_file, 'r') as f:
                encrypted_data = f.read().strip()
            if encrypted_data:
                decrypted = decrypt_license(encrypted_data)
                if decrypted:
                    license_info = json.loads(decrypted)
                    if 'expiry' in license_info:
                        try:
                            expiry_date = datetime.strptime(license_info['expiry'], '%Y-%m-%d')
                            if datetime.now() > expiry_date:
                                print(f"SECURITY VIOLATION: License expired on {license_info['expiry']}")
                                os._exit(1)  # Immediate termination for expired license
                        except Exception as e:
                            print(f"SECURITY VIOLATION: Invalid expiry date: {e}")
                            os._exit(1)
        
        # Basic validation without complex dependencies
        return _0x4c1c3ns3_ch3ck() and INTEGRITY_CHECK_ACTIVE
    except:
        return False

def _0x7f3a9b2c_s3cur1ty():
    """Tertiary security check - DO NOT REMOVE"""
    try:
        # Check if license file has been tampered with
        if os.path.exists("license.dat"):
            with open("license.dat", 'r') as f:
                data = f.read()
                if len(data) < 50:  # Minimum valid license size
                    return False
        return _0x4c1c3ns3_ch3ck()
    except:
        return False

def _validate_license_for_operation(operation_name="operation"):
    """Real-time license validation for critical operations - INSTANT REVOCATION CHECK"""
    try:
        if not LICENSE_ENFORCEMENT_ACTIVE:
            safe_print(f"🚨 SECURITY: License enforcement disabled during {operation_name}!")
            _emergency_shutdown(f"License enforcement disabled during {operation_name}")
        
        hardware_id = get_hardware_id()
        valid, message = validate_license_key("", hardware_id)
        if not valid:
            safe_print(f"🚨 OPERATION BLOCKED: License invalid during {operation_name}! {message}")
            _emergency_shutdown(f"License invalid during {operation_name}: {message}")
        
        # Check admin kill switch
        if _check_admin_kill_switch():
            safe_print(f"🚨 OPERATION TERMINATED: Admin kill switch activated during {operation_name}")
            _emergency_shutdown(f"Admin terminated during {operation_name}")
            
        return True
    except Exception as e:
        safe_print(f"🚨 SECURITY ERROR during {operation_name}: {e}")
        _emergency_shutdown(f"Security error during {operation_name}")
        return False

# Runtime integrity check
def _verify_app_integrity():
    """Verify application hasn't been tampered with"""
    try:
        # Check if critical functions exist
        critical_functions = ['get_hardware_id', 'validate_license_key', '_0x4c1c3ns3_ch3ck']
        for func_name in critical_functions:
            if func_name not in globals():
                os._exit(1)
        
        # Check if license file manipulation attempts
        if hasattr(sys.modules[__name__], '_license_bypassed'):
            os._exit(1)
            
        # Verify hardware ID consistency
        hw1 = get_hardware_id()
        time.sleep(0.1)
        hw2 = get_hardware_id()
        if hw1 != hw2:
            os._exit(1)
            
        return True
    except:
        os._exit(1)

# License file protection
def _protect_license_file():
    """Add protection against license file deletion"""
    def check_license_file():
        # Wait a bit before starting protection (allow activation window to show)
        time.sleep(60)  # Give 60 seconds for activation
        
        while True:
            try:
                if os.path.exists("license.dat"):
                    # Verify license file integrity
                    with open("license.dat", 'r') as f:
                        content = f.read().strip()
                    if not content or len(content) < 50:  # Minimum expected encrypted content length
                        safe_print("License file appears corrupted. Application will exit.")
                        time.sleep(5)  # Give user time to see message
                        os._exit(1)
                else:
                    # Only exit if we've been running for a while (not during initial activation)
                    if hasattr(_protect_license_file, 'protection_active'):
                        safe_print("License file was deleted during runtime. Application will exit.")
                        time.sleep(2)
                        os._exit(1)
                time.sleep(30)  # Check every 30 seconds
            except:
                if hasattr(_protect_license_file, 'protection_active'):
                    os._exit(1)
                time.sleep(30)
    
    thread = threading.Thread(target=check_license_file, daemon=True)
    thread.start()

# Anti-debugging check
def _anti_debug_check():
    """Basic anti-debugging measures"""
    try:
        import psutil
        # Check for common debugging processes
        suspicious_processes = ['ida', 'ollydbg', 'x64dbg', 'windbg', 'cheatengine', 'processhacker']
        for proc in psutil.process_iter(['name']):
            try:
                proc_name = proc.info['name'].lower()
                if any(debug_tool in proc_name for debug_tool in suspicious_processes):
                    os._exit(1)
            except:
                pass
    except ImportError:
        # psutil not available, skip check
        pass

# Runtime integrity check
def _verify_app_integrity():
    """Verify application hasn't been tampered with"""
    if not LICENSE_ENFORCEMENT_ACTIVE:
        os._exit(1)
    
    try:
        # Check if critical functions exist
        critical_functions = ['get_hardware_id', 'validate_license_key', '_0x4c1c3ns3_ch3ck', 
                             '_0x5d2e4f1a_v4l1d4t3', '_0x7f3a9b2c_s3cur1ty', '_validate_license_integrity']
        for func_name in critical_functions:
            if func_name not in globals():
                print(f"Critical function {func_name} missing - application integrity compromised")
                os._exit(1)
        
        # Check if license file manipulation attempts
        if hasattr(sys.modules[__name__], '_license_bypassed'):
            safe_print("License bypass attempt detected")
            os._exit(1)
            
        # Verify hardware ID consistency
        hw1 = get_hardware_id()
        time.sleep(0.1)
        hw2 = get_hardware_id()
        if hw1 != hw2:
            safe_print("Hardware ID inconsistency detected - potential bypass attempt")
            os._exit(1)
            
        # Additional integrity checks (simplified for stability)
        # These will be enforced during runtime operations
        if not LICENSE_ENFORCEMENT_ACTIVE:
            safe_print("License enforcement disabled")
            os._exit(1)
            
        return True
    except Exception as e:
        print(f"Integrity check failed: {e}")
        os._exit(1)

# Smart element detection class
class SmartElementFinder:
    def __init__(self, driver, wait_time=10):  # Reduced from 15 to 10 seconds
        self.driver = driver
        self.wait = WebDriverWait(driver, wait_time)
        self.short_wait = WebDriverWait(driver, 3)  # Reduced from 5 to 3 seconds  
        self.actions = ActionChains(driver)
    
    def find_clickable_element(self, selectors, description="element"):
        """Find and return the first clickable element from multiple selectors"""
        for i, selector in enumerate(selectors):
            try:
                element = self.short_wait.until(EC.element_to_be_clickable((By.XPATH, selector)))
                return element
            except TimeoutException:
                continue
        
        # If all selectors failed, try with longer wait on first selector
        try:
            return self.wait.until(EC.element_to_be_clickable((By.XPATH, selectors[0])))
        except TimeoutException:
            # Final fallback - look for any visible button in common UI contexts
            fallback_selectors = [
                '//button[not(@disabled) and not(contains(@style, "display: none"))]',
                '//div[@role="button" and not(contains(@style, "display: none"))]',
                '//span[@role="button" and not(contains(@style, "display: none"))]',
                '//input[@type="submit" and not(@disabled)]'
            ]
            
            for fallback in fallback_selectors:
                try:
                    elements = self.driver.find_elements(By.XPATH, fallback)
                    if elements:
                        # Return the most likely candidate (usually the last one in modals)
                        return elements[-1] if len(elements) > 1 else elements[0]
                except:
                    continue
                    
            raise TimeoutException(f"Could not find {description} with any of the provided selectors or fallbacks")
    
    def smart_click(self, element, description="element"):
        """Perform smart clicking with multiple fallback methods"""
        methods = [
            lambda: element.click(),
            lambda: self.driver.execute_script("arguments[0].click();", element),
            lambda: self.actions.move_to_element(element).click().perform(),
            lambda: self.driver.execute_script("arguments[0].dispatchEvent(new MouseEvent('click', {bubbles: true}));", element)
        ]
        
        for i, method in enumerate(methods):
            try:
                self.driver.execute_script("arguments[0].scrollIntoView({block: 'center', behavior: 'smooth'});", element)
                time.sleep(0.3)
                method()
                time.sleep(0.5)
                return True
            except Exception as e:
                if i == len(methods) - 1:
                    raise Exception(f"All click methods failed for {description}: {e}")
                continue
        return False
    
    def smart_input(self, element, text, description="input"):
        """Smart text input with multiple methods"""
        methods = [
            lambda: self._clear_and_type(element, text),
            lambda: self._js_clear_and_type(element, text),
            lambda: self._action_clear_and_type(element, text)
        ]
        
        for method in methods:
            try:
                self.driver.execute_script("arguments[0].scrollIntoView({block: 'center'});", element)
                time.sleep(0.2)
                method()
                time.sleep(0.3)
                return True
            except Exception:
                continue
        raise Exception(f"All input methods failed for {description}")
    
    def _clear_and_type(self, element, text):
        element.clear()
        time.sleep(0.1)
        element.send_keys(text)
    
    def _js_clear_and_type(self, element, text):
        self.driver.execute_script("arguments[0].value = '';", element)
        self.driver.execute_script("arguments[0].focus();", element)
        element.send_keys(text)
    
    def _action_clear_and_type(self, element, text):
        self.actions.move_to_element(element).click().key_down(Keys.CONTROL).send_keys('a').key_up(Keys.CONTROL).send_keys(text).perform()
    
    def wait_for_url_change(self, current_url, timeout=8, expected_contains=None):  # Reduced from 10 to 8 seconds
        """Wait for URL to change from current URL with faster polling"""
        end_time = time.time() + timeout
        while time.time() < end_time:
            try:
                new_url = self.driver.current_url
                if new_url != current_url:
                    if expected_contains is None or expected_contains in new_url:
                        return new_url
                time.sleep(0.2)  # Faster polling - reduced from 0.5 to 0.2
            except Exception:
                time.sleep(0.2)
        return None
    
    def wait_for_page_load(self, timeout=10):
        """Wait for page to fully load"""
        return self.wait.until(lambda driver: driver.execute_script("return document.readyState") == "complete")

# Multi-language support dictionary
MULTI_LANG_TRANSLATIONS = {
    'next': ['Next', 'Weiter', 'Suivant', '次へ', 'Далее', 'Próximo', 'Siguiente', 'Avanti', 'Volgende', 'Nästa', 'Następny', 'Próxima', 'Dalej', 'Naprej', 'Järgmine', 'Sljedeći', 'Нататък', 'Επόμενο', 'Järgmine', 'Sonraki'],
    'save': ['Save', 'Speichern', 'Enregistrer', '保存', 'Сохранить', 'Salvar', 'Guardar', 'Salva', 'Opslaan', 'Spara', 'Zapisz', 'Salvar', 'Zapisz', 'Shrani', 'Salvesta', 'Spremi', 'Запази', 'Αποθήκευση', 'Kaydet'],
    'create': ['Create', 'Erstellen', 'Créer', '作成', 'Создать', 'Criar', 'Crear', 'Crea', 'Maken', 'Skapa', 'Utwórz', 'Criar', 'Utwórz', 'Ustvari', 'Loo', 'Stvori', 'Създай', 'Δημιουργία', 'Oluştur'],
    'get_backup_codes': ['Get backup codes', 'Backup-Codes abrufen', 'Obtenir des codes de secours', 'バックアップコードを取得', 'Получить резервные коды', 'Obter códigos de backup', 'Obtener códigos de respaldo', 'Ottieni codici di backup', 'Back-upcodes ophalen', 'Hämta säkerhetskoder', 'Pobierz kody zapasowe', 'Obter códigos de backup', 'Pobierz kody zapasowe', 'Pridobi varnostne kode', 'Hangi varukoode', 'Dohvati sigurnosne kodove', 'Вземи резервни кодове', 'Λήψη εφεδρικών κωδικών', 'Yedek kodları al'],
    'turn_on': ['Turn on', 'Einschalten', 'Activer', '有効にする', 'Включить', 'Ativar', 'Activar', 'Attiva', 'Inschakelen', 'Aktivera', 'Włącz', 'Ativar', 'Włącz', 'Vklopi', 'Lülita sisse', 'Uključi', 'Включи', 'Ενεργοποίηση', 'Aç'],
    'done': ['Done', 'Fertig', 'Terminé', '完了', 'Готово', 'Concluído', 'Listo', 'Fatto', 'Klaar', 'Klar', 'Gotowe', 'Concluído', 'Gotowe', 'Končano', 'Valmis', 'Gotovo', 'Готово', 'Τέλος', 'Tamam']
}

def get_multi_language_selector(button_type, base_selector_template):
    """Generate multi-language XPath selector for buttons"""
    if button_type not in MULTI_LANG_TRANSLATIONS:
        return base_selector_template
    
    translations = MULTI_LANG_TRANSLATIONS[button_type]
    text_conditions = []
    
    for text in translations:
        text_conditions.extend([
            f'text()="{text}"',
            f'contains(text(), "{text}")',
            f'normalize-space(text())="{text}"',
            f'contains(normalize-space(text()), "{text}")',
            f'translate(text(), "ABCDEFGHIJKLMNOPQRSTUVWXYZ", "abcdefghijklmnopqrstuvwxyz")="{text.lower()}"'
        ])
    
    combined_condition = ' or '.join(text_conditions)
    return base_selector_template.format(combined_condition)

# Thread lock for file operations
file_lock = threading.Lock()

def collect_backup_codes(driver, finder, email, status_queue):
    """Collect 2 backup codes and return them as a list"""
    codes = []
    try:
        status_queue.put(("status", f"[{email}] Navigating to backup codes page"))
        driver.get("https://myaccount.google.com/two-step-verification/backup-codes?hl=en")
        finder.wait_for_page_load()
        time.sleep(3)

        # Click the 'Get backup codes' button or check if codes are already visible
        # ENGLISH-ONLY backup codes button selectors (PRIMARY - Language forced to English)
        get_codes_selectors = [
            # ENGLISH-FIRST SELECTORS - These should ALWAYS work with language forcing
            '//span[@jsname="V67aGc" and text()="Get backup codes"]',
            '//button[.//span[text()="Get backup codes"]]',
            '//button[text()="Get backup codes"]',
            '//span[text()="Get backup codes"]',
            '//button[contains(text(), "Get backup codes")]',
            '//span[contains(text(), "Get backup codes")]',
            '//button[contains(text(), "backup codes")]',
            '//span[contains(text(), "backup codes")]',
            
            # STRUCTURAL SELECTORS (no text dependency)
            '//span[@jsname="V67aGc" and contains(@class, "AeBiU-vQzf8d")]',
            '//button[contains(@class, "VfPpkd-LgbsSe")]',
            '//div[@role="button"]',
            '//button[@type="button"]'
        ]
        
        # EMERGENCY FALLBACK - Multi-language (should NOT be needed)
        if len(get_codes_selectors) < 15:  # Add fallbacks only if needed
            backup_code_texts = MULTI_LANG_TRANSLATIONS['get_backup_codes']
            for text in backup_code_texts[1:3]:  # Only add first 3 fallback languages
                get_codes_selectors.append(f'//button[.//span[contains(text(), "{text}")]]')
        
        # First check if backup codes are already visible before trying to click
        status_queue.put(("status", f"[{email}] Checking if backup codes are already visible"))
        existing_codes = driver.find_elements(By.XPATH, '//span[string-length(normalize-space(text())) >= 8 and string-length(normalize-space(text())) <= 12] | //div[string-length(normalize-space(text())) >= 8 and string-length(normalize-space(text())) <= 12]')
        
        if len(existing_codes) >= 2:
            status_queue.put(("status", f"[{email}] Backup codes appear to already be visible, skipping button click"))
        else:
            # Try to click the button to show codes
            get_codes_btn = None
            for selector in get_codes_selectors:
                try:
                    get_codes_btn = finder.find_clickable_element([selector], "Get backup codes button")
                    break
                except Exception:
                    continue
                    
            if get_codes_btn:
                finder.smart_click(get_codes_btn, "Get backup codes button")
                status_queue.put(("status", f"[{email}] ✅ Clicked Get backup codes button"))
                time.sleep(2)  # Reduced from 3 to 2 seconds for faster code loading
            else:
                status_queue.put(("status", f"[{email}] Get backup codes button not found, checking for existing codes"))

        # CRITICAL FIX: Force click on <span class="AeBiU-RLmnJb"></span> if present to load codes
        try:
            # Look for the special span that triggers code loading (from your example)
            trigger_spans = driver.find_elements(By.XPATH, '//span[contains(@class, "AeBiU-RLmnJb")]')
            if trigger_spans:
                status_queue.put(("status", f"[{email}] Found {len(trigger_spans)} <span class='AeBiU-RLmnJb'> elements, clicking to load backup codes"))
                for i, span in enumerate(trigger_spans):
                    try:
                        finder.smart_click(span, f"Backup codes trigger span {i+1}")
                        status_queue.put(("status", f"[{email}] ✅ Clicked trigger span {i+1}"))
                        time.sleep(2)
                    except Exception as e:
                        status_queue.put(("status", f"[{email}] Could not click trigger span {i+1}: {e}"))
            else:
                status_queue.put(("status", f"[{email}] No <span class='AeBiU-RLmnJb'> elements found"))
        except Exception as e:
            status_queue.put(("status", f"[{email}] Error searching for trigger spans: {e}"))

        # Wait for codes to appear and collect first 2
        time.sleep(2)  # Extra wait for codes to load
        
        # Try multiple strategies to find backup codes
        code_selectors = [
            # Google's common backup code patterns
            '//div[contains(@class, "backup-code")]',
            '//span[contains(@class, "backup-code")]',
            '//code',
            # Generic patterns for backup codes (usually 8-10 chars)
            '//span[string-length(normalize-space(text())) >= 8 and string-length(normalize-space(text())) <= 12 and contains(translate(text(), "0123456789abcdefghijklmnopqrstuvwxyz", "00000000000000000000000000000000000"), "0")]',
            '//div[string-length(normalize-space(text())) >= 8 and string-length(normalize-space(text())) <= 12 and contains(translate(text(), "0123456789abcdefghijklmnopqrstuvwxyz", "00000000000000000000000000000000000"), "0")]',
            # Material Design components
            '//div[contains(@class, "VfPpkd-") and string-length(normalize-space(text())) >= 8 and string-length(normalize-space(text())) <= 12]',
            '//span[contains(@class, "VfPpkd-") and string-length(normalize-space(text())) >= 8 and string-length(normalize-space(text())) <= 12]',
            # Generic text elements that might contain codes
            '//p[string-length(normalize-space(text())) >= 8 and string-length(normalize-space(text())) <= 12]',
            '//li[string-length(normalize-space(text())) >= 8 and string-length(normalize-space(text())) <= 12]',
            # Font family often used for codes
            '//span[contains(@style, "monospace") or contains(@class, "monospace")]',
            # Any element with exactly 8-10 alphanumeric characters
            '//*[string-length(normalize-space(text())) >= 8 and string-length(normalize-space(text())) <= 12 and not(contains(text(), " "))]'
        ]
        
        status_queue.put(("status", f"[{email}] Searching for backup codes with {len(code_selectors)} different strategies"))
        
        for i, selector in enumerate(code_selectors):
            try:
                status_queue.put(("status", f"[{email}] Trying selector {i+1}/{len(code_selectors)}"))
                code_elements = driver.find_elements(By.XPATH, selector)
                status_queue.put(("status", f"[{email}] Found {len(code_elements)} potential code elements"))
                
                if code_elements:
                    for j, element in enumerate(code_elements):
                        try:
                            code_text = element.text.strip()
                            status_queue.put(("status", f"[{email}] Element {j+1} text: '{code_text}' (length: {len(code_text)})"))
                            
                            # More flexible validation for backup codes
                            if (len(code_text) >= 6 and len(code_text) <= 15 and 
                                code_text.replace('-', '').replace(' ', '').replace('_', '').isalnum() and
                                not any(word in code_text.lower() for word in ['backup', 'code', 'get', 'show', 'generate', 'click', 'button'])):
                                codes.append(code_text)
                                status_queue.put(("status", f"[{email}] 🔑 Found backup code: {code_text}"))
                                if len(codes) >= 2:
                                    break
                        except Exception as e:
                            status_queue.put(("status", f"[{email}] Error reading element {j+1}: {e}"))
                            continue
                    
                    if len(codes) >= 2:
                        break
            except Exception as e:
                status_queue.put(("status", f"[{email}] Selector {i+1} failed: {e}"))
                continue
        
        # If still no codes found, try to get all text content and parse manually
        if not codes:
            try:
                status_queue.put(("status", f"[{email}] Fallback: scanning all page text for backup codes"))
                page_text = driver.find_element(By.TAG_NAME, "body").text
                
                # Look for patterns that look like backup codes
                import re
                # Pattern: 8-12 alphanumeric characters, possibly with hyphens
                code_pattern = r'\b[a-zA-Z0-9]{4}[-\s]?[a-zA-Z0-9]{4}\b|\b[a-zA-Z0-9]{8,12}\b'
                potential_codes = re.findall(code_pattern, page_text)
                
                for code in potential_codes:
                    clean_code = code.replace(' ', '').replace('-', '')
                    if (len(clean_code) >= 6 and len(clean_code) <= 15 and 
                        clean_code.isalnum() and
                        not any(word in clean_code.lower() for word in ['backup', 'code', 'get', 'show', 'generate'])):
                        codes.append(code)
                        status_queue.put(("status", f"[{email}] 🔑 Found backup code via regex: {code}"))
                        if len(codes) >= 2:
                            break
            except Exception as e:
                status_queue.put(("status", f"[{email}] Fallback text parsing failed: {e}"))
        
        if codes:
            status_queue.put(("status", f"[{email}] 🔑 Collected {len(codes)} backup codes: {', '.join(codes[:2])}"))
        else:
            status_queue.put(("error", f"[{email}] Could not extract backup codes from page"))
            
    except Exception as e:
        status_queue.put(("error", f"[{email}] Backup code collection failed: {e}"))
    
    return codes[:2]  # Return only first 2 codes

def save_app_password(email, password, app_password, backup_codes=None):
    """Save successful account with app password and backup codes to CSV immediately"""
    with file_lock:
        file_exists = os.path.isfile("successful_accounts.csv")
        with open("successful_accounts.csv", mode="a", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            if not file_exists:
                writer.writerow(["Email", "Password", "App Password", "Backup Code 1", "Backup Code 2"])
            
            # Ensure we have 2 backup codes or empty strings
            code1 = backup_codes[0] if backup_codes and len(backup_codes) > 0 else ""
            code2 = backup_codes[1] if backup_codes and len(backup_codes) > 1 else ""
            
            # Write immediately to CSV without timestamp
            writer.writerow([email, password, app_password, code1, code2])
            f.flush()  # Force immediate write to disk
            os.fsync(f.fileno())  # Ensure data is written to disk immediately
            
        # Return confirmation of what was saved
        return {
            'email': email,
            'app_password': app_password,
            'backup_codes': [code1, code2] if code1 or code2 else []
        }

def save_failed_account(email, password, reason):
    """Save failed account with reason to CSV"""
    with file_lock:
        file_exists = os.path.isfile("failed_accounts.csv")
        with open("failed_accounts.csv", mode="a", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            if not file_exists:
                writer.writerow(["Email", "Password", "Failure Reason"])
            writer.writerow([email, password, reason])

def check_existing_2fa(driver, finder, email, status_queue):
    """Check if 2-Step Verification is already enabled on the account"""
    try:
        # Check current URL for 2FA indicators
        current_url = driver.current_url.lower()
        
        # Look for 2FA related URLs
        twofa_indicators = [
            'twosv',
            'two-step',
            '',
            'signinoptions/twosv',
            'two-step-verification'
        ]
        
        if any(indicator in current_url for indicator in twofa_indicators):
            status_queue.put(("status", f"[{email}] 🔍 Checking if 2FA is already enabled..."))
            
            # Look for elements that indicate 2FA is already active
            twofa_active_selectors = [
                '//div[contains(text(), "2-Step Verification is on")]',
                '//div[contains(text(), "You\'re protected")]',
                '//span[contains(text(), "Turn off")]',
                '//button[contains(text(), "Turn off")]',
                '//div[contains(@class, "enabled") and contains(text(), "2-Step")]',
                '//div[contains(text(), "Backup codes")]//ancestor::div[contains(@class, "card")]',
                '//span[contains(text(), "Get backup codes")]',
                '//div[text()="On" or text()="Enabled"]//ancestor::div[contains(text(), "2-Step")]'
            ]
            
            # Check page content for 2FA status - be more specific to avoid false positives
            page_source = driver.page_source.lower()
            # Only check for very specific indicators that 2FA is actually enabled
            specific_2fa_enabled_phrases = [
                '2-step verification is on',
                'you\'re protected with 2-step',
                'turn off 2-step verification',
                'get backup codes'
            ]
            
            # Only return True if we find specific enabled indicators AND we're on a 2FA settings page
            if any(phrase in page_source for phrase in specific_2fa_enabled_phrases):
                # Double check we're actually on a 2FA settings page
                if any(indicator in current_url for indicator in twofa_indicators):
                    status_queue.put(("status", f"[{email}] ✅ Confirmed: 2FA is already enabled on this account"))
                    return True
                else:
                    status_queue.put(("status", f"[{email}] ⚠️ Found 2FA text but not on 2FA page - continuing setup"))
                    return False
                
            # Check for specific elements
            for selector in twofa_active_selectors:
                try:
                    elements = driver.find_elements(By.XPATH, selector)
                    if elements:
                        status_queue.put(("status", f"[{email}] ✅ Found 2FA active indicator: {selector[:50]}..."))
                        return True
                except:
                    continue
        
        return False
        
    except Exception as e:
        status_queue.put(("status", f"[{email}] ⚠️ Error checking 2FA status: {e}"))
        return False

def google_automation_worker(email, password, status_queue, stop_event):
    """Worker function for Google automation running in a separate thread"""
    # CRITICAL: IMMEDIATE EXPIRY CHECK - TERMINATE IF EXPIRED
    try:
        _check_license_expiry_immediate()
    except SystemExit:
        status_queue.put(("error", f"[{email}] 🚫 LICENSE EXPIRED - AUTOMATION TERMINATED"))
        return
    
    # 🔒 ENHANCED SECURITY: Check for bypass attempts before automation
    bypass_files = ["master_access.key", "bypass.key", "unlock.key", "override.key", "admin.key"]
    for bypass_file in bypass_files:
        if os.path.exists(bypass_file):
            status_queue.put(("error", f"[{email}] 🚨 Unauthorized bypass detected"))
            return
    
    # CRITICAL: Multiple license validation layers before starting automation
    if not _0x4c1c3ns3_ch3ck():
        status_queue.put(("error", f"[{email}] ❌ License validation failed"))
        return
    
    if not _0x5d2e4f1a_v4l1d4t3():
        status_queue.put(("error", f"[{email}] ❌ Security validation failed"))
        return
        
    if not _0x7f3a9b2c_s3cur1ty():
        status_queue.put(("error", f"[{email}] ❌ License integrity check failed"))
        return
    
    # 🔒 ENHANCED SECURITY: Check for bypass attempts before automation
    bypass_files = ["master_access.key", "bypass.key", "unlock.key", "override.key", "admin.key"]
    for bypass_file in bypass_files:
        if os.path.exists(bypass_file):
            status_queue.put(("error", f"[{email}] 🚨 Unauthorized bypass detected"))
            return
    
    # Additional runtime verification
    _verify_app_integrity()
    
    # Verify license hasn't expired during runtime
    hardware_id = get_hardware_id()
    valid, message = validate_license_key("", hardware_id)
    if not valid:
        status_queue.put(("error", f"[{email}] ❌ License validation failed: {message}"))
        return
    
    # 🛡️ WINDOWS SYSTEM OPTIMIZATION FOR EXE STABILITY 🛡️
    try:
        if os.name == 'nt':  # Windows only
            # Set process priority to prevent resource conflicts
            import subprocess
            try:
                subprocess.run(['wmic', 'process', 'where', f'ProcessId={os.getpid()}', 'CALL', 'setpriority', '32768'], 
                             capture_output=True, timeout=5)
            except Exception:
                pass  # Continue if wmic fails
                
            # Set memory management flags for stability
            try:
                import ctypes
                # Enable heap debugging for crash prevention in compiled EXE
                kernel32 = ctypes.windll.kernel32
                kernel32.SetProcessWorkingSetSize(ctypes.c_void_p(-1), ctypes.c_size_t(-1), ctypes.c_size_t(-1))
            except Exception:
                pass
                
    except Exception:
        pass  # Don't fail if optimization fails

    # COMPREHENSIVE TIMEOUT AND FAILURE DETECTION
    automation_start_time = time.time()
    max_automation_time = 600  # 10 minutes maximum per account
    
    def check_timeout():
        elapsed = time.time() - automation_start_time
        if elapsed > max_automation_time:
            return True, f"⏱️ Account timeout ({elapsed:.1f}s) - Skipping to next account"
        return False, ""
    
    def handle_account_failure(reason, skip_to_next=True):
        """Handle account failure with user-friendly messaging"""
        status_queue.put(("error", f"[{email}] ❌ {reason}"))
        save_failed_account(email, password, reason)
        status_queue.put(("update_status", (email, 'Failed')))
        
        if skip_to_next:
            status_queue.put(("status", f"[{email}] ⏭️ Skipping to next account..."))
    
    status_queue.put(("status", f"[{email}] 🚀 Starting automation (Max time: {max_automation_time//60} minutes)"))
    
    try:
        if stop_event.is_set():
            return
            
        status_queue.put(("status", f"Starting automation for {email}"))
        status_queue.put(("status", f"[{email}] 🌐 Language forcing enabled - Browser will use English interface"))
        
        # Enhanced Chrome options for speed and reliability
        temp_dir = None
        driver = None
        try:
            # Create optimized temporary directory
            temp_dir = tempfile.mkdtemp(prefix=f"chrome_smart_{email.replace('@', '_').replace('.', '_')}_")
            
            options = Options()
            # Anti-detection measures
            options.add_argument("--disable-blink-features=AutomationControlled")
            options.add_experimental_option("excludeSwitches", ["enable-automation"])
            options.add_experimental_option('useAutomationExtension', False)
            
            # MAXIMUM SPEED PERFORMANCE OPTIMIZATIONS + EXE CRASH PREVENTION
            options.add_argument("--no-sandbox")
            options.add_argument("--disable-dev-shm-usage")
            options.add_argument("--disable-gpu")
            options.add_argument("--disable-gpu-sandbox")
            options.add_argument("--disable-software-rasterizer")
            options.add_argument("--disable-web-security")
            options.add_argument("--disable-features=VizDisplayCompositor")
            options.add_argument("--disable-extensions")
            options.add_argument("--disable-plugins")
            options.add_argument("--disable-images")  # Faster page loading
            options.add_argument("--disable-javascript-harmony-shipping")
            options.add_argument("--disable-background-timer-throttling")
            options.add_argument("--disable-renderer-backgrounding")
            options.add_argument("--disable-backgrounding-occluded-windows")
            options.add_argument("--disable-client-side-phishing-detection")
            options.add_argument("--disable-sync")
            options.add_argument("--disable-default-apps")
            options.add_argument("--no-first-run")
            options.add_argument("--no-default-browser-check")
            options.add_argument("--disable-logging")
            options.add_argument("--disable-gpu-logging")
            options.add_argument("--silent")
            
            # 🛡️ CRITICAL EXE STABILITY OPTIONS - PREVENT CHROME CRASHES 🛡️
            options.add_argument("--disable-webgl")
            options.add_argument("--disable-webgl2")
            options.add_argument("--disable-3d-apis")
            options.add_argument("--disable-accelerated-2d-canvas")
            options.add_argument("--disable-accelerated-video-decode")
            options.add_argument("--disable-canvas-aa")
            options.add_argument("--disable-2d-canvas-clip-aa")
            options.add_argument("--disable-gl-drawing-for-tests")
            options.add_argument("--disable-accelerated-mjpeg-decode")
            options.add_argument("--disable-accelerated-video-encode")
            options.add_argument("--use-gl=swiftshader")
            options.add_argument("--enable-unsafe-webgpu")
            options.add_argument("--disable-features=WebGL,WebGL2,DirectWrite")
            options.add_argument("--disable-d3d11")
            options.add_argument("--disable-directwrite-for-ui")
            options.add_argument("--force-cpu-draw")
            options.add_argument("--disable-gpu-process-crash-limit")
            options.add_argument("--disable-crash-reporter")
            options.add_argument("--crash-dumps-dir=NUL")
            options.add_argument("--disable-breakpad")
            
            # 🖥️ ADDITIONAL GPU CONTEXT FAILURE PREVENTION - STOPS GUI DISAPPEARING
            options.add_argument("--disable-gpu-channel")
            options.add_argument("--disable-gpu-driver-bug-workarounds")
            options.add_argument("--disable-gpu-memory-buffer-compositor-resources")
            options.add_argument("--disable-gpu-memory-buffer-video-frames")
            options.add_argument("--disable-shared-context-for-webgl")
            options.add_argument("--disable-context-sharing")
            options.add_argument("--disable-gpu-virtualization")
            options.add_argument("--force-gpu-mem-available-mb=1024")
            options.add_argument("--disable-video-capture-service")
            options.add_argument("--disable-gcm-registration-endpoint")
            
            # 🔇 ADDITIONAL ERROR SUPPRESSION - REDUCE CHROME ERROR MESSAGES
            options.add_argument("--disable-logging")
            options.add_argument("--log-level=3")  # Only fatal errors
            options.add_argument("--silent")
            options.add_argument("--disable-gpu-host-process")
            options.add_argument("--disable-ipc-flooding-protection")
            options.add_argument("--disable-renderer-accessibility")
            options.add_argument("--disable-speech-api")
            options.add_argument("--disable-file-system")
            options.add_argument("--disable-notifications")
            options.add_argument("--disable-desktop-notifications")
            
            # SPEED BOOST: Enhanced performance flags
            options.add_argument("--memory-pressure-off")
            options.add_argument("--max_old_space_size=4096")
            options.add_argument("--aggressive-cache-discard")
            options.add_argument("--disable-background-networking")
            options.add_argument("--disable-component-update")
            options.add_argument("--disable-domain-reliability")
            options.add_argument("--disable-features=TranslateUI")
            options.add_argument("--disable-ipc-flooding-protection")
            options.add_argument("--enable-fast-unload")
            options.add_argument("--aggressive")
            
            # User data and debugging
            options.add_argument(f"--user-data-dir={temp_dir}")
            options.add_argument("--remote-debugging-port=0")
            
            # 🌍 COMPREHENSIVE ENGLISH LANGUAGE ENFORCEMENT - NO LANGUAGE ERRORS 🌍
            # Force English at multiple levels to prevent any language switching
            options.add_argument("--lang=en-US")
            options.add_argument("--accept-lang=en-US,en;q=1.0")
            options.add_argument("--accept-language=en-US,en;q=1.0")
            options.add_argument("--disable-translate")
            options.add_argument("--disable-extensions-http-throttling")
            options.add_argument("--disable-locale-switching-bho")
            
            # Advanced language enforcement
            options.add_argument("--force-app-mode")
            options.add_argument("--disable-features=TranslateUI,Translate")
            options.add_argument("--disable-background-downloads")
            options.add_argument("--disable-locale-override")
            options.add_argument("--force-ui-direction=ltr")  # Left-to-right for English
            options.add_argument("--disable-component-extensions-with-background-pages")
            
            # Set comprehensive language preferences
            language_prefs = {
                "intl.accept_languages": "en-US,en",
                "spellcheck.dictionary": "en-US", 
                "translate.enabled": False,
                "translate_ranker_model.heuristic_only": True,
                "translate.ranker_model": "",
                "profile.default_content_setting_values.translate": 2,
                "profile.default_content_settings.popups": 0,
                "profile.content_settings.exceptions.language_settings": {
                    "*": {"setting": 1, "en": {"setting": 1}}
                }
            }
            options.add_experimental_option("prefs", language_prefs)
            
            # FORCE ALL GOOGLE SERVICES TO ENGLISH
            options.add_experimental_option("prefs", {
                # PRIMARY LANGUAGE FORCING
                "intl.accept_languages": "en-US,en",
                "intl.selected_language": "en-US", 
                "intl.charset_default": "UTF-8",
                "intl.locale_matching": "lookup",
                
                # DISABLE ALL TRANSLATION
                "translate.enabled": False,
                "translate_whitelists": {},
                "translate_denied_count_for_language": {},
                "translate.blocked_languages": ["*"],
                "translate_site_blacklist_with_time": {},
                "translate_accepted_count_for_language": {},
                "translate_ranker_model_url": "",
                "translate_ranker_model_version": 0,
                
                # FORCE GOOGLE TO ENGLISH
                "google.services.language": "en-US",
                "google.services.country": "US",
                "google.services.tld": "com",
                
                # BROWSER INTERFACE ENGLISH
                "browser.enable_spellchecking": False,
                "spellcheck.dictionary": "en-US",
                "spellcheck.use_spelling_service": False,
                "browser.language": "en-US",
                "profile.default_content_setting_values.notifications": 2,
                "profile.default_content_settings.popups": 0,
                "profile.managed_default_content_settings.images": 2
            })
            
            # Set optimal permissions
            os.chmod(temp_dir, 0o755)

            # 🛡️ ROBUST WEBDRIVER CREATION WITH CRASH PROTECTION 🛡️
            service = Service()
            retry_count = 0
            max_retries = 3
            
            while retry_count < max_retries:
                try:
                    driver = webdriver.Chrome(service=service, options=options)
                    status_queue.put(("status", f"[{email}] ✅ Chrome WebDriver created successfully (attempt {retry_count + 1})"))
                    break
                except Exception as webdriver_error:
                    retry_count += 1
                    status_queue.put(("status", f"[{email}] ⚠️ WebDriver creation attempt {retry_count} failed: {str(webdriver_error)}"))
                    
                    if retry_count >= max_retries:
                        status_queue.put(("status", f"[{email}] ❌ WebDriver creation failed after {max_retries} attempts"))
                        status_queue.put(("error", f"[{email}] Chrome WebDriver initialization error: {str(webdriver_error)}"))
                        raise webdriver_error
                    
                    # Brief delay before retry
                    time.sleep(2)
            
            # MAXIMUM LANGUAGE FORCING - OVERRIDE EVERYTHING TO ENGLISH
            driver.execute_script("Object.defineProperty(navigator, 'webdriver', {get: () => undefined})")
            
            # AGGRESSIVE ENGLISH FORCING - OVERRIDE ALL LANGUAGE DETECTION
            driver.execute_script("""
                // FORCE ENGLISH LANGUAGE - OVERRIDE EVERYTHING
                Object.defineProperty(navigator, 'language', {get: () => 'en-US', configurable: false});
                Object.defineProperty(navigator, 'languages', {get: () => ['en-US', 'en'], configurable: false});
                
                // OVERRIDE ALL LOCALE AND REGION DETECTION
                if (typeof Intl !== 'undefined') {
                    // Force all date/time formatting to English
                    const originalDateTimeFormat = Intl.DateTimeFormat;
                    Intl.DateTimeFormat = function(...args) {
                        args[0] = 'en-US';
                        return originalDateTimeFormat.apply(this, args);
                    };
                    
                    // Force all number formatting to English
                    const originalNumberFormat = Intl.NumberFormat;
                    Intl.NumberFormat = function(...args) {
                        args[0] = 'en-US';
                        return originalNumberFormat.apply(this, args);
                    };
                    
                    // Force all collation to English
                    const originalCollator = Intl.Collator;
                    Intl.Collator = function(...args) {
                        args[0] = 'en-US';
                        return originalCollator.apply(this, args);
                    };
                }
                
                // OVERRIDE TIMEZONE AND LOCALE DETECTION
                try {
                    Object.defineProperty(Intl.DateTimeFormat.prototype, 'resolvedOptions', {
                        value: function() {
                            return {
                                locale: 'en-US',
                                language: 'en',
                                region: 'US',
                                timeZone: 'America/New_York',
                                calendar: 'gregory',
                                numberingSystem: 'latn'
                            };
                        },
                        configurable: false
                    });
                } catch(e) {}
                
                // FORCE DOCUMENT LANGUAGE
                if (document.documentElement) {
                    document.documentElement.lang = 'en-US';
                    document.documentElement.setAttribute('lang', 'en-US');
                }
                
                // OVERRIDE ANY GOOGLE-SPECIFIC LANGUAGE DETECTION
                window.google_lang = 'en';
                window.google_locale = 'en-US';
                window.hl = 'en';
                window.gl = 'US';
            """)            
            
            # Other anti-detection measures
            driver.execute_script("Object.defineProperty(navigator, 'plugins', {get: () => [1, 2, 3, 4, 5]})")
            
            # Initialize smart finder
            finder = SmartElementFinder(driver, 20)
        
        except Exception as chrome_error:
            status_queue.put(("error", f"[{email}] Chrome setup failed: {chrome_error}"))
            save_failed_account(email, password, "CS")
            if temp_dir and os.path.exists(temp_dir):
                try:
                    shutil.rmtree(temp_dir, ignore_errors=True)
                except:
                    pass
            return

        # Step 1: Smart navigation to Google login
        if stop_event.is_set():
            status_queue.put(("status", f"[{email}] Stopped - Closing browser..."))
            try:
                driver.quit()
                status_queue.put(("success", f"[{email}] ✅ Browser closed after stop"))
            except:
                pass
            return
            
        status_queue.put(("status", f"[{email}] Smart navigation to Google login"))
        
        # Multiple navigation attempts with different URLs and LANGUAGE FORCING
        login_urls = [
            "https://accounts.google.com/signin/v2/identifier?hl=en",  # Force English with hl parameter
            "https://accounts.google.com/signin?hl=en-US",
            "https://accounts.google.com/?hl=en"
        ]
        
        navigation_success = False
        for url in login_urls:
            try:
                driver.get(url)
                finder.wait_for_page_load()
                
                # Force English language on the page via JavaScript
                try:
                    driver.execute_script("""
                        // Force English language on Google pages
                        if (window.location.hostname.includes('google.com')) {
                            // Try to force language parameter
                            const url = new URL(window.location);
                            if (!url.searchParams.has('hl') || url.searchParams.get('hl') !== 'en') {
                                url.searchParams.set('hl', 'en');
                                window.location.href = url.toString();
                            }
                        }
                    """)                    
                    time.sleep(1)  # Wait for potential redirect
                except Exception:
                    pass  # Continue if JavaScript fails
                
                # Verify we're on the right page
                if "accounts.google.com" in driver.current_url:
                    navigation_success = True
                    status_queue.put(("status", f"[{email}] ✅ Successfully navigated to Google login (English forced)"))
                    break
            except Exception as e:
                continue
        
        if not navigation_success:
            raise Exception("Failed to navigate to Google login page")
        
        time.sleep(0.5)  # Brief stabilization for fast processing

        # Step 2: Smart email entry with validation
        if stop_event.is_set():
            status_queue.put(("status", f"[{email}] Stopped - Closing browser..."))
            try:
                driver.quit()
                status_queue.put(("success", f"[{email}] ✅ Browser closed after stop"))
            except:
                pass
            return
            
        status_queue.put(("status", f"[{email}] Smart email entry"))
        
        # Enhanced email field selectors
        email_selectors = [
            '//input[@id="identifierId"]',
            '//input[@type="email"]',
            '//input[@name="identifier"]',
            '//input[contains(@class, "whsOnd")]',
            '//input[@autocomplete="username"]'
        ]
        
        try:
            email_element = finder.find_clickable_element(email_selectors, "email input field")
            
            # Smart input with validation
            finder.smart_input(email_element, email, "email field")
            
            # Verify email was entered correctly
            entered_email = driver.execute_script("return arguments[0].value;", email_element)
            if entered_email != email:
                status_queue.put(("status", f"[{email}] Retrying email entry - verification failed"))
                finder.smart_input(email_element, email, "email field")
            
            # Smart Enter key press
            try:
                email_element.send_keys(Keys.RETURN)
            except Exception:
                # Fallback: look for Next button
                next_selectors = [
                    '//button[@id="identifierNext"]',
                    '//button[contains(@class, "VfPpkd-LgbsSe")]//span[contains(text(), "Next")]',
                    '//input[@type="submit"]'
                ]
                next_btn = finder.find_clickable_element(next_selectors, "next button")
                finder.smart_click(next_btn, "next button")
            
            # Wait for URL change or password page
            time.sleep(1)  # Reduced wait time for faster detection
            status_queue.put(("status", f"[{email}] ✅ Email entered successfully"))
            
            # IMMEDIATE MULTI-STAGE VERIFICATION DETECTION AFTER EMAIL ENTRY
            verification_detected = False
            verification_message = ""
            
            # STAGE 1: Quick initial check (0.5s after email)
            for attempt in range(1, 6):  # 5 attempts over 2.5 seconds max
                current_url = driver.current_url.lower() 
                page_source = driver.page_source.lower()
                
                # SPECIFIC VERIFICATION URLs ONLY (avoid normal password pages)
                specific_verification_urls = [
                    "challenge/recaptcha",      # reCAPTCHA challenge 
                    "deniedsigninrejected",     # Account blocked
                    "selectchallenge",          # Challenge selection
                    "challenge/ipp",            # Phone verification
                    "challenge/kmp"             # Additional verification
                ]
                
                # EXCLUDE normal password URLs that contain "challenge" but are NOT verification
                normal_password_urls = [
                    "challenge/pwd",            # Normal password page - NOT a challenge
                    "signin/challenge/pwd"      # Another normal password pattern
                ]
                
                # Check if it's a normal password URL first (SKIP detection)
                is_normal_password_url = any(pattern in current_url for pattern in normal_password_urls)
                
                if is_normal_password_url:
                    # This is a normal password page, not a verification challenge
                    status_queue.put(("status", f"[{email}] ✅ Normal password page detected (attempt {attempt}) - continuing"))
                    break  # Exit detection loop and continue to password entry
                
                # Check for specific verification URLs
                url_verification_detected = any(pattern in current_url for pattern in specific_verification_urls)
                
                if url_verification_detected:
                    # URL clearly shows verification - immediate detection
                    detected_urls = [url for url in specific_verification_urls if url in current_url]
                    status_queue.put(("status", f"[{email}] 🔍 VERIFICATION URL DETECTED (attempt {attempt}): {detected_urls}"))
                    
                    if "recaptcha" in current_url:
                        verification_message = "❌ Google reCAPTCHA verification required after email entry - Cannot proceed automatically"
                    elif "deniedsigninrejected" in current_url:
                        verification_message = "❌ Account access denied - Cannot proceed automatically"
                    else:
                        verification_message = "❌ Google verification challenge triggered after email - Cannot proceed automatically" 
                    
                    verification_detected = True
                    break
                
                # TEXT-BASED DETECTION (secondary)
                high_priority_patterns = [
                    "confirm you're not a robot",
                    "prove you're not a robot", 
                    "verify it's you",
                    "captcha",
                    "recaptcha"
                ]
                
                text_verification_detected = any(pattern in page_source for pattern in high_priority_patterns)
                
                if text_verification_detected:
                    # Check if we're NOT on a normal password page
                    password_indicators = ['type="password"', 'name="password"', 'enter your password']
                    is_password_page = any(indicator in page_source for indicator in password_indicators)
                    
                    if not is_password_page:
                        detected_patterns = [pattern for pattern in high_priority_patterns if pattern in page_source][:2]
                        status_queue.put(("status", f"[{email}] 🔍 VERIFICATION TEXT DETECTED (attempt {attempt}): {detected_patterns}"))
                        
                        if "robot" in page_source or "captcha" in page_source:
                            verification_message = "❌ Google robot verification required after email entry - Cannot proceed automatically"
                        else:
                            verification_message = "❌ Google identity verification required after email entry - Cannot proceed automatically"
                        
                        verification_detected = True
                        break
                
                # Quick wait before next attempt (faster detection)
                if attempt < 5:
                    time.sleep(0.2)  # Reduced to 0.2s for maximum speed
            
            if verification_detected:
                # Log the current URL for debugging
                status_queue.put(("status", f"[{email}] 🔍 Current URL: {current_url[:80]}..."))
                status_queue.put(("error", f"[{email}] {verification_message}"))
                save_failed_account(email, password, verification_message)
                
                # Close browser immediately after email verification detection - NO SCREENSHOTS
                status_queue.put(("status", f"[{email}] 🔄 Closing browser after email verification challenge..."))
                try:
                    driver.quit()
                    status_queue.put(("success", f"[{email}] ✅ Browser closed after email verification challenge"))
                except:
                    pass
                return
            
            # IMMEDIATE RECAPTCHA DETECTION AFTER EMAIL ENTRY (Scenario 1)
            if "challenge/recaptcha" in current_url or "recaptcha" in current_url.lower():
                if "confirm you're not a robot" in page_source or "verify it's you" in page_source:
                    status_queue.put(("error", f"[{email}] ❌ RECAPTCHA REQUIRED: Google requires CAPTCHA verification after email entry"))
                    status_queue.put(("status", f"[{email}] 🚫 Reason: reCAPTCHA challenge detected - Cannot proceed automatically"))
                    status_queue.put(("status", f"[{email}] 🔄 SKIPPING to next account immediately"))
                    
                    save_failed_account(email, password, "RC")
                    status_queue.put(("update_status", (email, 'CAPTCHA Required')))
                    
                    # Close browser immediately
                    try:
                        driver.quit()
                        status_queue.put(("success", f"[{email}] ✅ Browser closed - reCAPTCHA detected"))
                    except:
                        pass
                    return
            
            # If no verification detected, continue to password entry
            status_queue.put(("status", f"[{email}] ✅ No verification challenges detected - proceeding to password entry"))
            
        except Exception as e:
            status_queue.put(("error", f"[{email}] Email entry failed: {e}"))
            save_failed_account(email, password, "EE")
            
            # Close browser immediately after email failure
            status_queue.put(("status", f"[{email}] 🔄 Closing browser after email entry failure..."))
            try:
                driver.quit()
                status_queue.put(("success", f"[{email}] ✅ Browser closed after email failure"))
            except:
                pass
            return

        # Step 3: Smart password entry with multiple strategies
        if stop_event.is_set():
            status_queue.put(("status", f"[{email}] Stopped - Closing browser..."))
            try:
                if driver:
                    driver.quit()
                status_queue.put(("success", f"[{email}] ✅ Browser closed after stop"))
            except:
                pass
            return
            
        status_queue.put(("status", f"[{email}] Smart password entry"))
        
        # Enhanced password field detection
        password_selectors = [
            '//input[@name="Passwd"]',
            '//input[@type="password"]',
            '//input[@id="password"]',
            '//input[contains(@class, "whsOnd") and @type="password"]',
            '//input[@autocomplete="current-password"]',
            '//input[@aria-label="Enter your password"]'
        ]
        
        try:
            # Wait for password page to load
            time.sleep(3)
            
            password_element = finder.find_clickable_element(password_selectors, "password input field")
            
            # Smart password input
            finder.smart_input(password_element, password, "password field")
            
            # Verify password was entered (without revealing it)
            password_length = driver.execute_script("return arguments[0].value.length;", password_element)
            if password_length != len(password):
                status_queue.put(("status", f"[{email}] Retrying password entry - length mismatch"))
                finder.smart_input(password_element, password, "password field")
            
            # Smart submission
            current_url = driver.current_url
            try:
                password_element.send_keys(Keys.RETURN)
            except Exception:
                # Fallback: look for Next/Sign in button
                submit_selectors = [
                    '//button[@id="passwordNext"]',
                    '//button[contains(@class, "VfPpkd-LgbsSe")]//span[contains(text(), "Next")]',
                    '//input[@type="submit"]',
                    '//button[@type="submit"]'
                ]
                submit_btn = finder.find_clickable_element(submit_selectors, "password submit button")
                finder.smart_click(submit_btn, "password submit button")
            
            # ⚡🚨 ULTRA-PRIORITY: IMMEDIATE URL CHECK AFTER PASSWORD SUBMISSION 🚨⚡ 
            # Check URL immediately to catch challenge redirects before any waiting
            try:
                immediate_url = driver.current_url.lower()
                status_queue.put(("status", f"[{email}] 🔥 IMMEDIATE URL CHECK: {immediate_url[:80]}..."))
                
                # INSTANT challenge detection - ONLY for definite 2FA/reCAPTCHA (NOT challenge/pwd)
                # CRITICAL: Exclude challenge/pwd to allow proper wrong password detection
                if ("challenge/dp" in immediate_url or 
                    "challenge/recaptcha" in immediate_url or 
                    "challenge/selection" in immediate_url or
                    "challenge/sms" in immediate_url or
                    "challenge/totp" in immediate_url) and "challenge/pwd" not in immediate_url:
                    
                    challenge_type = "2FA/reCAPTCHA"
                    if "challenge/recaptcha" in immediate_url:
                        challenge_type = "reCAPTCHA"
                    elif "challenge/dp" in immediate_url:
                        challenge_type = "2FA challenge/dp" 
                    elif "challenge/selection" in immediate_url:
                        challenge_type = "2FA selection"
                    elif "challenge/sms" in immediate_url:
                        challenge_type = "2FA SMS"
                    elif "challenge/totp" in immediate_url:
                        challenge_type = "2FA TOTP"
                    
                    status_queue.put(("error", f"[{email}] 🚨 IMMEDIATE {challenge_type} DETECTED - ULTRA PRIORITY SKIP"))
                    error_code = "RC" if "recaptcha" in challenge_type else "Tsv"
                    save_failed_account(email, password, error_code)
                    status_queue.put(("update_status", (email, f'{challenge_type} Detected')))
                    
                    try:
                        driver.quit()
                        status_queue.put(("success", f"[{email}] ✅ ULTRA PRIORITY: Browser closed - {challenge_type}"))
                    except:
                        pass
                    
                    status_queue.put(("status", f"[{email}] 🚨 ULTRA PRIORITY RETURN - NO HANGING"))
                    return
                
                # SPECIAL: If challenge/pwd detected, allow time for page content to load for wrong password detection
                if "challenge/pwd" in immediate_url:
                    status_queue.put(("status", f"[{email}] ⚠️ challenge/pwd detected - allowing time for content analysis"))
                    # Don't return yet - let normal flow handle wrong password vs 2FA distinction
                
                # DEBUG: Log what URL we're on after password submission
                status_queue.put(("status", f"[{email}] 📍 CURRENT URL AFTER PASSWORD: {immediate_url}"))
                status_queue.put(("status", f"[{email}] 🔍 Proceeding to wait for error messages or success..."))
                    
            except Exception as e:
                status_queue.put(("status", f"[{email}] ⚠️ Immediate URL check error: {e}"))
            
            # SPEED OPTIMIZED: Allow time for error messages to appear after password submission
            status_queue.put(("status", f"[{email}] ⚡ Waiting for page response after password submission..."))
            time.sleep(2.5)  # Increased to allow error messages to appear (Google can be slow)
            
            # Optimized dynamic content loading with shorter intervals + immediate challenge checks
            for retry in range(2):  # Reduced from 3 to 2 retries
                try:
                    # IMMEDIATE challenge check in each retry iteration (EXCLUDE challenge/pwd)
                    quick_url = driver.current_url.lower()
                    definite_2fa_patterns = ["challenge/dp", "challenge/recaptcha", "challenge/selection", "challenge/sms", "challenge/totp"]
                    # Only trigger immediate exit for definite 2FA, not challenge/pwd (needs content analysis)
                    if any(pattern in quick_url for pattern in definite_2fa_patterns) and "challenge/pwd" not in quick_url:
                        status_queue.put(("status", f"[{email}] 🚨 DEFINITE 2FA DETECTED IN RETRY LOOP - IMMEDIATE EXIT"))
                        break  # Exit retry loop immediately to reach detection logic
                    
                    # Quick page ready check with ultra-short timeout for challenge detection
                    try:
                        # Use very short timeout to prevent hanging on challenge pages
                        wait_short = WebDriverWait(driver, 2)  # Super short timeout
                        wait_short.until(lambda driver: driver.execute_script("return document.readyState") == "complete")
                    except:
                        # If page doesn't load quickly, proceed anyway to check for challenges
                        status_queue.put(("status", f"[{email}] ⚡ Page load timeout - proceeding with challenge detection"))
                    
                    time.sleep(0.2)  # Ultra-reduced for maximum speed
                    break
                except:
                    if retry < 1:  # Shorter retry cycle
                        time.sleep(0.2)  # Ultra-reduced retry wait
            
            # Get current page state with enhanced debugging 
            current_url = driver.current_url.lower()
            
            # CRITICAL: For challenge/pwd URLs, wait a bit more for page content to load
            # This ensures proper wrong password vs normal password input distinction
            if "challenge/pwd" in current_url:
                status_queue.put(("status", f"[{email}] ⚠️ challenge/pwd detected - waiting for content analysis"))
                time.sleep(1.5)  # Extra time for page content to load for proper error detection
                
            page_source = driver.page_source.lower()
            
            # ⚡🚨 ABSOLUTE TOP PRIORITY: IMMEDIATE CHALLENGE DETECTION 🚨⚡
            # MUST happen BEFORE any other logic to prevent hanging
            status_queue.put(("status", f"[{email}] 🚨🚨🚨 CRITICAL DEBUG: Challenge detection reached!"))
            status_queue.put(("status", f"[{email}] ⚡ IMMEDIATE CHALLENGE CHECK: {current_url[:80]}..."))
            status_queue.put(("status", f"[{email}] 🔍 FULL URL: {current_url}"))
            
            # AGGRESSIVE DEBUG: Check every URL pattern
            status_queue.put(("status", f"[{email}] 🔍 Contains 'challenge/recaptcha': {'challenge/recaptcha' in current_url}"))
            status_queue.put(("status", f"[{email}] 🔍 Contains 'challenge/dp': {'challenge/dp' in current_url}"))
            status_queue.put(("status", f"[{email}] 🔍 Contains 'challenge/selection': {'challenge/selection' in current_url}"))
            status_queue.put(("status", f"[{email}] 🔍 Contains 'challenge/pwd': {'challenge/pwd' in current_url}"))
            
            # SCENARIO 1: reCAPTCHA Challenge - INSTANT DETECTION & SKIP
            if "challenge/recaptcha" in current_url:
                status_queue.put(("error", f"[{email}] ❌ reCAPTCHA DETECTED: Immediate skip triggered"))
                status_queue.put(("status", f"[{email}] 🚫 URL: challenge/recaptcha found"))
                save_failed_account(email, password, "RC")
                status_queue.put(("update_status", (email, 'reCAPTCHA Required')))
                try:
                    driver.quit()
                    status_queue.put(("success", f"[{email}] ✅ Browser closed - reCAPTCHA (TOP PRIORITY)"))
                except:
                    pass
                status_queue.put(("status", f"[{email}] 🚨 RETURNING FROM RECAPTCHA DETECTION"))
                return
            
            # SCENARIO 2: 2FA Challenge URLs - INSTANT DETECTION & SKIP  
            # Enhanced pattern matching for all challenge URL variations
            challenge_patterns = ["challenge/dp", "challenge/selection", "challenge/pwd", "challenge/sms", "challenge/totp", "/v3/signin/challenge/", "/signin/challenge/"]
            detected_pattern = None
            for pattern in challenge_patterns:
                if pattern in current_url:
                    detected_pattern = pattern
                    break
            
            if detected_pattern:
                # CRITICAL: Only treat as wrong password if there are DEFINITIVE error indicators
                # Be very specific to avoid false positives on legitimate 2FA pages
                
                # High-confidence wrong password indicators (very specific)
                definitive_wrong_password_indicators = [
                    "wrong password. try again", "password is incorrect", "incorrect password",
                    "password you entered is incorrect", "couldn't sign you in",
                    "click forgot password to reset it"
                ]
                
                # Multiple indicator check (less specific individually, but multiple = higher confidence)
                general_indicators = ["wrong password", "try again", "forgot password"]
                general_matches = sum(1 for indicator in general_indicators if indicator in page_source)
                
                # Only treat as wrong password if:
                # 1. Has definitive wrong password phrase, OR
                # 2. Has multiple (2+) general indicators together
                has_definitive_error = any(indicator in page_source for indicator in definitive_wrong_password_indicators)
                has_multiple_indicators = general_matches >= 2
                
                is_actual_wrong_password = has_definitive_error or has_multiple_indicators
                
                # If it's actually a wrong password error, prioritize WP over 2FA
                if is_actual_wrong_password:
                    status_queue.put(("error", f"[{email}] ❌ WRONG PASSWORD detected in challenge URL: {detected_pattern}"))
                    status_queue.put(("status", f"[{email}] 🚫 Prioritizing WP over 2FA detection"))
                    save_failed_account(email, password, "WP")
                    status_queue.put(("update_status", (email, 'Wrong Password')))
                    try:
                        driver.quit()
                        status_queue.put(("success", f"[{email}] ✅ Browser closed - Wrong Password (PRIORITY)"))
                    except:
                        pass
                    status_queue.put(("status", f"[{email}] 🚨 RETURNING FROM WRONG PASSWORD (PRIORITY)"))
                    return
                
                # Only treat as 2FA if no wrong password indicators found
                challenge_type = detected_pattern
                status_queue.put(("error", f"[{email}] ❌ 2FA DETECTED: {challenge_type} immediate skip triggered"))
                status_queue.put(("status", f"[{email}] 🚫 URL: {challenge_type} found"))
                status_queue.put(("status", f"[{email}] 🚨 CRITICAL: Preventing hang on 2FA challenge page"))
                save_failed_account(email, password, "Tsv")
                status_queue.put(("update_status", (email, 'Already Protected')))
                try:
                    driver.quit()
                    status_queue.put(("success", f"[{email}] ✅ Browser closed - {challenge_type} (TOP PRIORITY)"))
                except:
                    pass
                status_queue.put(("status", f"[{email}] 🚨 RETURNING FROM 2FA DETECTION"))
                return
            
            # SCENARIO 3: Wrong Password - SPECIFIC detection to avoid false positives
            # Only detect DEFINITIVE wrong password errors, not general text
            
            # High-confidence wrong password indicators (very specific phrases)
            definitive_wrong_password_indicators = [
                "wrong password. try again", "password is incorrect", "incorrect password",
                "password you entered is incorrect", "couldn't sign you in",
                "click forgot password to reset it"
            ]
            
            # Multiple indicator check for medium confidence
            general_indicators = ["wrong password", "try again", "forgot password"]
            general_matches = sum(1 for indicator in general_indicators if indicator in page_source)
            
            # ENHANCED: Check for wrong password on multiple URL patterns
            wrong_password_url_patterns = ["challenge/pwd", "signin", "/password", "/signin/v2"]
            has_wrong_password_url = any(pattern in current_url for pattern in wrong_password_url_patterns)
            
            # Only treat as wrong password if:
            # 1. Has definitive wrong password phrase, OR
            # 2. Has multiple (2+) general indicators together
            has_definitive_error = any(indicator in page_source for indicator in definitive_wrong_password_indicators)
            has_multiple_indicators = general_matches >= 2
            is_actual_wrong_password = has_definitive_error or has_multiple_indicators
            
            if has_wrong_password_url and is_actual_wrong_password:
                status_queue.put(("error", f"[{email}] ❌ WRONG PASSWORD DETECTED: Immediate skip triggered"))
                status_queue.put(("status", f"[{email}] 🚫 URL: challenge/pwd with actual error content"))
                save_failed_account(email, password, "WP")
                status_queue.put(("update_status", (email, 'Wrong Password')))
                try:
                    driver.quit()
                    status_queue.put(("success", f"[{email}] ✅ Browser closed - Wrong password (TOP PRIORITY)"))
                except:
                    pass
                status_queue.put(("status", f"[{email}] 🚨 RETURNING FROM WRONG PASSWORD DETECTION"))
                return
            
            # IMPORTANT: Normal password input URLs should continue processing
            wrong_password_url_patterns = ["challenge/pwd", "signin", "/password", "/signin/v2"]
            has_wrong_password_url = any(pattern in current_url for pattern in wrong_password_url_patterns)
            
            # Use specific detection logic for consistency
            definitive_wrong_password_indicators = [
                "wrong password. try again", "password is incorrect", "incorrect password",
                "password you entered is incorrect", "couldn't sign you in",
                "click forgot password to reset it"
            ]
            general_indicators = ["wrong password", "try again", "forgot password"]
            general_matches = sum(1 for indicator in general_indicators if indicator in page_source)
            
            has_definitive_error = any(indicator in page_source for indicator in definitive_wrong_password_indicators)
            has_multiple_indicators = general_matches >= 2
            is_actual_wrong_password = has_definitive_error or has_multiple_indicators
            
            if has_wrong_password_url and not is_actual_wrong_password:
                status_queue.put(("status", f"[{email}] ✅ Normal password input page detected - continuing with password entry"))
            
            # ✅ NO IMMEDIATE CHALLENGES DETECTED - Continue with normal flow
            status_queue.put(("status", f"[{email}] 🚨 DEBUG: No immediate challenges detected - continuing analysis"))
            status_queue.put(("status", f"[{email}] 🔍 This means challenge detection was reached but no patterns matched"))
            
            # ENHANCED DEBUG LOGGING for 2FA detection troubleshooting
            status_queue.put(("status", f"[{email}] 🔍 DEBUG: Current URL: {current_url[:100]}..."))
            
            # Debug: Check for key content indicators
            debug_indicators = {
                "2fa_url_patterns": ["challenge/selection", "challenge/dp", "challenge/ipp", "challenge/kmp"],
                "2fa_content_patterns": ["2-step verification", "make sure it's really you", "check your", "google sent a notification"],
                "success_indicators": ["myaccount.google.com", "accounts.google.com/b/0/manageaccount"],
                "error_indicators": ["wrong password", "incorrect password", "try again"]
            }
            
            for category, patterns in debug_indicators.items():
                matches = [p for p in patterns if (p in current_url if "url" in category else p in page_source)]
                if matches:
                    status_queue.put(("status", f"[{email}] 🔍 DEBUG {category}: {matches[:2]}"))  # Limit to first 2 matches
            
            # CRITICAL: Check for wrong password BEFORE checking for success
            # This prevents wrong password pages from being misinterpreted as successful logins
            
            # Enhanced wrong password detection with ABSOLUTE PRIORITY
            definitive_wrong_password_indicators = [
                "wrong password. try again", "password is incorrect", "incorrect password",
                "password you entered is incorrect", "couldn't sign you in",
                "click forgot password to reset it"
            ]
            general_indicators = ["wrong password", "try again", "forgot password"]
            general_matches = sum(1 for indicator in general_indicators if indicator in page_source)
            
            has_definitive_error = any(indicator in page_source for indicator in definitive_wrong_password_indicators)
            has_multiple_indicators = general_matches >= 2
            is_wrong_password_error = has_definitive_error or has_multiple_indicators
            
            if is_wrong_password_error:
                status_queue.put(("error", f"[{email}] ❌ WRONG PASSWORD DETECTED - ABSOLUTE PRIORITY"))
                status_queue.put(("status", f"[{email}] 🚫 Definitive: {has_definitive_error}, Multiple: {has_multiple_indicators}"))
                save_failed_account(email, password, "WP")
                status_queue.put(("update_status", (email, 'Wrong Password')))
                try:
                    driver.quit()
                    status_queue.put(("success", f"[{email}] ✅ Browser closed - Wrong Password (ABSOLUTE PRIORITY)"))
                except:
                    pass
                return
            
            # PRIORITY 1: Check for successful login to account dashboard (ONLY if no wrong password)
            successful_login_urls = [
                "myaccount.google.com",
                "accounts.google.com/b/0/manageaccount", 
                "accounts.google.com/signin/continue",
                "myaccount.google.com/?utm_source=sign_in_no_continue"  # User's specific success URL
            ]
            
            successful_login = any(success_url in current_url for success_url in successful_login_urls)
            
            if successful_login:
                status_queue.put(("status", f"[{email}] ✅ Password correct - Successfully reached account dashboard"))
                status_queue.put(("status", f"[{email}] ✅ Skipping challenge detection - Already on success page"))
                # Skip all challenge detection and continue to login verification/2FA setup
            else:
                # OPTIMIZED 3-SCENARIO DETECTION SYSTEM FOR MAXIMUM SPEED (only if NOT successful)
                status_queue.put(("status", f"[{email}] 🔍 URL: {current_url[:80]}..."))
            
            # SCENARIO 1: reCAPTCHA after email entry - IMMEDIATE DETECTION & SKIP
            # Handle exact user scenario: https://accounts.google.com/v3/signin/challenge/recaptcha
            recaptcha_patterns = [
                "verify it's you",
                "confirm you're not a robot", 
                "prove you're not a robot",
                "to help keep your account safe"
            ]
            
            # ⚡ ULTRA-FAST IMMEDIATE DETECTION - ABSOLUTE PRIORITY ⚡
            # These URL patterns ALWAYS require immediate skip - NO content verification needed
            
            # SCENARIO 1: reCAPTCHA Challenge - IMMEDIATE SKIP
            if "challenge/recaptcha" in current_url:
                status_queue.put(("error", f"[{email}] ❌ RECAPTCHA CHALLENGE: Immediate detection"))
                status_queue.put(("status", f"[{email}] 🚫 URL: challenge/recaptcha detected"))
                status_queue.put(("status", f"[{email}] 🔄 IMMEDIATE SKIP - Account flagged for verification"))
                
                save_failed_account(email, password, "RC")
                status_queue.put(("update_status", (email, 'reCAPTCHA Required')))
                
                try:
                    driver.quit()
                    status_queue.put(("success", f"[{email}] ✅ Browser closed - reCAPTCHA (immediate)"))
                except:
                    pass
                return
            
            # SCENARIO 2: 2FA Challenge URLs - IMMEDIATE SKIP
            if "challenge/dp" in current_url or "challenge/selection" in current_url:
                status_queue.put(("error", f"[{email}] ❌ 2FA CHALLENGE: Immediate detection"))
                status_queue.put(("status", f"[{email}] 🚫 URL: {current_url}"))
                status_queue.put(("status", f"[{email}] 🔄 IMMEDIATE SKIP - Account has 2FA enabled"))
                
                save_failed_account(email, password, "Tsv")
                status_queue.put(("update_status", (email, 'Already Protected')))
                
                try:
                    driver.quit()
                    status_queue.put(("success", f"[{email}] ✅ Browser closed - 2FA (immediate)"))
                except:
                    pass
                return
            
            # SCENARIO 3: Wrong Password Detection - SPECIFIC & IMMEDIATE SKIP (case-insensitive) 
            page_source_lower = page_source.lower()
            
            # High-confidence wrong password indicators (very specific phrases)
            definitive_wrong_password_indicators = [
                "wrong password. try again", "password is incorrect", "incorrect password",
                "password you entered is incorrect", "couldn't sign you in",
                "click forgot password to reset it"
            ]
            
            # Multiple indicator check for medium confidence
            general_indicators = ["wrong password", "try again", "forgot password"]
            general_matches = sum(1 for indicator in general_indicators if indicator in page_source_lower)
            
            # Enhanced URL pattern matching
            wrong_password_url_patterns = ["challenge/pwd", "signin", "/password", "/signin/v2"]
            has_wrong_password_url = any(pattern in current_url for pattern in wrong_password_url_patterns)
            
            # Only treat as wrong password if definitive or multiple indicators
            has_definitive_error = any(indicator in page_source_lower for indicator in definitive_wrong_password_indicators)
            has_multiple_indicators = general_matches >= 2
            is_actual_wrong_password = has_definitive_error or has_multiple_indicators
            
            if has_wrong_password_url and is_actual_wrong_password:
                status_queue.put(("error", f"[{email}] ❌ WRONG PASSWORD: Incorrect password detected"))
                status_queue.put(("status", f"[{email}] 🚫 URL: challenge/pwd with error content"))
                status_queue.put(("status", f"[{email}] 🔄 IMMEDIATE SKIP - Password verification failed"))
                
                save_failed_account(email, password, "WP")
                status_queue.put(("update_status", (email, 'Wrong Password')))
                
                try:
                    driver.quit()
                    status_queue.put(("success", f"[{email}] ✅ Browser closed - Wrong password (immediate)"))
                except:
                    pass
                return

            
            # PRIORITY 3: Check for security challenges (only if NO password error)
            # Enhanced challenge URL patterns (excluding password error URLs)
            challenge_patterns = [
                "challenge/selection", 
                "signin/challenge/ipp",
                "signin/challenge/az", 
                "signin/challenge/kmp",
                "deniedsigninrejected",
                "selectchallenge"
            ]
            
            # Only consider v3/signin/challenge if it's NOT a pwd error page
            if "v3/signin/challenge" in current_url and "challenge/pwd" not in current_url:
                challenge_patterns.append("v3/signin/challenge")
            
            challenge_detected = any(pattern in current_url for pattern in challenge_patterns)
            
            if challenge_detected:
                matching_pattern = next(pattern for pattern in challenge_patterns if pattern in current_url)
                status_queue.put(("status", f"[{email}] 🎯 Security challenge detected - Pattern: '{matching_pattern}'"))
                # Analyze the type of challenge
                challenge_content_patterns = {
                    "2fa": ["2-step verification", "two-step verification", "authenticator app", "enter verification code"],
                    "security": ["make sure it's really you", "verify it's you", "verify that it's you", "help keep your account safe", "unusual activity"],
                    "captcha": ["prove you're not a robot", "confirm you're not a robot", "captcha", "recaptcha"],
                    "phone": ["phone number", "text message", "phone verification"]
                }
                
                challenge_type = "unknown"
                for ctype, patterns in challenge_content_patterns.items():
                    if any(pattern in page_source for pattern in patterns):
                        challenge_type = ctype
                        break
                
                status_queue.put(("status", f"[{email}] 🔍 Challenge type detected: {challenge_type.upper()}"))
                
                if challenge_type == "2fa":
                    status_queue.put(("error", f"[{email}] ❌ 2-STEP VERIFICATION REQUIRED: Password correct but account requires 2FA verification"))
                    status_queue.put(("status", f"[{email}] 🚫 Reason: Google requires 2-Step Verification - Account already protected"))
                    save_failed_account(email, password, "Tsv")
                    status_queue.put(("update_status", (email, 'Already Protected')))
                elif challenge_type in ["security", "captcha", "phone"]:
                    status_queue.put(("error", f"[{email}] ❌ GOOGLE SECURITY CHALLENGE: Password correct but {challenge_type.upper()} verification required"))
                    status_queue.put(("status", f"[{email}] 🚫 Reason: Google security challenge detected - Cannot proceed automatically"))
                    save_failed_account(email, password, "SC")
                    status_queue.put(("update_status", (email, 'Challenge Required')))
                else:
                    # Generic challenge
                    status_queue.put(("error", f"[{email}] ❌ GOOGLE CHALLENGE: Password correct but additional verification required"))
                    status_queue.put(("status", f"[{email}] 🚫 Challenge URL: {current_url[:80]}..."))
                    save_failed_account(email, password, "SC")
                    status_queue.put(("update_status", (email, 'Challenge Required')))
                
                status_queue.put(("status", f"[{email}] 🔄 Closing browser IMMEDIATELY - Moving to next account"))
                
                # Close browser immediately
                try:
                    driver.quit()
                    status_queue.put(("success", f"[{email}] ✅ Browser closed - {challenge_type.upper()} challenge detected"))
                except:
                    pass
                return
            
            # PRIORITY 4: If no success, no password error, no challenge - unknown state  
            else:
                status_queue.put(("status", f"[{email}] ⚠️ Unknown login state detected"))
                status_queue.put(("status", f"[{email}] 🔍 URL: {current_url[:100]}..."))
                
                # Treat as unknown error and continue to login verification
                status_queue.put(("status", f"[{email}] ⏭️ Proceeding to login verification step"))
            
            # PRIORITY 3: Check for security challenges (only if NO password error)
            # Enhanced challenge URL patterns (excluding password error URLs)
            challenge_patterns = [
                "challenge/selection", 
                "signin/challenge/ipp",
                "signin/challenge/az", 
                "signin/challenge/kmp",
                "deniedsigninrejected",
                "selectchallenge"
            ]
            
            # Only consider v3/signin/challenge if it's NOT a pwd error page
            if "v3/signin/challenge" in current_url and "challenge/pwd" not in current_url:
                challenge_patterns.append("v3/signin/challenge")
            
            challenge_detected = any(pattern in current_url for pattern in challenge_patterns)
            
            if challenge_detected:
                matching_pattern = next(pattern for pattern in challenge_patterns if pattern in current_url)
                status_queue.put(("status", f"[{email}] 🎯 Security challenge detected - Pattern: '{matching_pattern}'"))
                
                # Analyze the type of challenge
                challenge_content_patterns = {
                    "2fa": ["2-step verification", "two-step verification", "authenticator app", "enter verification code"],
                    "security": ["make sure it's really you", "verify it's you", "verify that it's you", "help keep your account safe", "unusual activity"],
                    "captcha": ["prove you're not a robot", "confirm you're not a robot", "captcha", "recaptcha"],
                    "phone": ["phone number", "text message", "phone verification"]
                }
                
                challenge_type = "unknown"
                for ctype, patterns in challenge_content_patterns.items():
                    if any(pattern in page_source for pattern in patterns):
                        challenge_type = ctype
                        break
                
                status_queue.put(("status", f"[{email}] 🔍 Challenge type detected: {challenge_type.upper()}"))
                
                if challenge_type == "2fa":
                    status_queue.put(("error", f"[{email}] ❌ 2-STEP VERIFICATION REQUIRED: Password correct but account requires 2FA verification"))
                    status_queue.put(("status", f"[{email}] 🚫 Reason: Google requires 2-Step Verification - Account already protected"))
                    save_failed_account(email, password, "Tsv")
                    status_queue.put(("update_status", (email, 'Already Protected')))
                else:
                    status_queue.put(("error", f"[{email}] ❌ GOOGLE SECURITY CHALLENGE: Password correct but {challenge_type.upper()} verification required"))
                    status_queue.put(("status", f"[{email}] 🚫 Reason: Google security challenge detected - Cannot proceed automatically"))
                    save_failed_account(email, password, "SC")
                    status_queue.put(("update_status", (email, 'Challenge Required')))
                
                status_queue.put(("status", f"[{email}] 🔄 Closing browser IMMEDIATELY - Moving to next account"))
                
                # Close browser immediately
                try:
                    driver.quit()
                    status_queue.put(("success", f"[{email}] ✅ Browser closed - {challenge_type.upper()} challenge detected"))
                except:
                    pass
                return
            
            # PRIORITY 4: FINAL SAFETY CHECK - Catch any remaining 2FA URLs that might cause hanging
            # EXCLUDE challenge/pwd which is a normal password challenge, not 2FA
            elif (any(pattern in current_url for pattern in ["challenge/dp", "challenge/selection", "challenge/ipp", "challenge/kmp"]) and 
                  "challenge/pwd" not in current_url):
                status_queue.put(("status", f"[{email}] 🚨 SAFETY CHECK: Detected 2FA challenge URL that wasn't caught earlier"))
                status_queue.put(("error", f"[{email}] ❌ 2-STEP VERIFICATION: Account protected with 2FA (safety check detection)"))
                status_queue.put(("status", f"[{email}] 🔍 Safety URL: {current_url[:80]}..."))
                status_queue.put(("status", f"[{email}] 🔄 SKIPPING to next account immediately"))
                
                save_failed_account(email, password, "Tsv")
                status_queue.put(("update_status", (email, 'Already Protected')))
                
                try:
                    driver.quit()
                    status_queue.put(("success", f"[{email}] ✅ Browser closed - 2FA safety check"))
                except:
                    pass
                return
            
            # PRIORITY 5: If no success, no password error, no challenge - unknown state  
            else:
                status_queue.put(("status", f"[{email}] ⚠️ Unknown login state detected"))
                status_queue.put(("status", f"[{email}] 🔍 URL: {current_url[:100]}..."))
                
                # Final check: if URL contains any 2FA indicators, treat as 2FA
                # EXCLUDE challenge/pwd which is normal password flow, not 2FA
                if (any(indicator in current_url for indicator in ["2step", "twofactor", "verification"]) or 
                    ("challenge" in current_url and "challenge/pwd" not in current_url)):
                    status_queue.put(("status", f"[{email}] 🚨 FINAL 2FA CHECK: URL contains 2FA indicators"))
                    status_queue.put(("error", f"[{email}] ❌ 2-STEP VERIFICATION: Final safety detection"))
                    save_failed_account(email, password, "Tsv")
                    status_queue.put(("update_status", (email, 'Already Protected')))
                    
                    try:
                        driver.quit()
                        status_queue.put(("success", f"[{email}] ✅ Browser closed - Final 2FA check"))
                    except:
                        pass
                    return
                
                # Treat as unknown error and continue to login verification
                status_queue.put(("status", f"[{email}] ⏭️ Proceeding to login verification step"))
            
            # If no error detected, wait for successful login (reduced timeout for faster failure detection)
            new_url = finder.wait_for_url_change(current_url, timeout=8, expected_contains="myaccount")
            if new_url:
                status_queue.put(("status", f"[{email}] ✅ Password accepted, redirecting..."))
            
        except Exception as e:
            # Check for timeout first
            is_timeout, timeout_msg = check_timeout()
            if is_timeout:
                handle_account_failure(timeout_msg)
                try:
                    driver.quit()
                except:
                    pass
                return
            
            # Enhanced password error handling with specific error detection
            page_source = driver.page_source.lower() if driver else ""
            error_message = str(e).lower()
            
            user_friendly_message = ""
            
            # Specific Google error message patterns
            if any(phrase in error_message or phrase in page_source for phrase in [
                "wrong password", "incorrect password", "password is incorrect",
                "couldn't sign you in", "couldn't sign in", "try again"
            ]):
                user_friendly_message = "❌ Wrong password. Please check your password and try again."
            elif any(phrase in error_message or phrase in page_source for phrase in [
                "account locked", "account disabled", "suspended"
            ]):
                user_friendly_message = "❌ Account is locked or suspended. Contact Google support."
            elif any(phrase in error_message or phrase in page_source for phrase in [
                "captcha", "verification required", "unusual activity"
            ]):
                user_friendly_message = "❌ Account requires manual verification (CAPTCHA/unusual activity)."
            elif any(phrase in error_message or phrase in page_source for phrase in [
                "timeout", "connection", "network"
            ]):
                user_friendly_message = "❌ Network timeout or connection issue. Please try again later."
            else:
                user_friendly_message = f"❌ Password entry failed: {str(e)[:100]}..."
            
            # CRITICAL: Check if we actually succeeded despite the exception  
            try:
                current_url = driver.current_url.lower()
                if "myaccount.google.com" in current_url:
                    status_queue.put(("status", f"[{email}] ✅ Successfully reached account dashboard despite exception - continuing"))
                    # Don't call handle_account_failure - we actually succeeded!
                    # Continue to next step instead of returning
                else:
                    # Only treat as failure if we're NOT on success page
                    handle_account_failure(user_friendly_message)
                    
                    # Close browser immediately after password failure
                    status_queue.put(("status", f"[{email}] 🔄 Closing browser after password failure..."))
                    try:
                        driver.quit()
                        status_queue.put(("success", f"[{email}] ✅ Browser closed after password failure"))
                    except:
                        pass
                    return
            except:
                # If we can't check URL, treat as failure
                handle_account_failure(user_friendly_message)
                
                # Close browser immediately after password failure
                status_queue.put(("status", f"[{email}] 🔄 Closing browser after password failure..."))
                try:
                    driver.quit()
                    status_queue.put(("success", f"[{email}] ✅ Browser closed after password failure"))
                except:
                    pass
                return
            # End of challenge detection else block
            
        # Step 4: Smart login verification with comprehensive error detection
        try:
            status_queue.put(("status", f"[{email}] Verifying successful login"))
            
            # SPEED OPTIMIZED: Faster login verification (2 minutes max)
            login_start_time = time.time()
            login_timeout = 120  # Reduced from 180 to 120 seconds (2 minutes)
            
            # Multiple success indicators - expanded to catch more success scenarios
            success_patterns = [
                "myaccount.google.com",
                "accounts.google.com/ManageAccount", 
                "accounts.google.com/b/0/ManageAccount",
                "accounts.google.com/signin/v2/challenge/selection",  # Sometimes shows briefly before redirect
                "accounts.google.com/accountsettings",
                "google.com/account",
                "myaccount.google.com/?utm_source=sign_in_no_continue"  # User's specific success URL
            ]
            
            login_verified = False
            verification_attempts = 0
            max_attempts = 4  # Reduced from 6 to 4 attempts for faster processing
            
            while not login_verified and verification_attempts < max_attempts:
                verification_attempts += 1
                
                # Check if we've exceeded overall timeout
                if time.time() - login_start_time > login_timeout:
                    raise Exception("Login verification timeout (3 minutes) - Account may be slow or blocked")
                
                current_url = driver.current_url
                page_source = driver.page_source.lower()
                
                # Debug logging for troubleshooting
                status_queue.put(("status", f"[{email}] 🔍 Login check - URL: {current_url[:60]}..."))
                
                # Check for success first - if successful, skip all verification challenge checks
                for pattern in success_patterns:
                    if pattern in current_url:
                        login_verified = True
                        break
                
                if login_verified:
                    status_queue.put(("status", f"[{email}] ✅ Successfully reached account dashboard - login verified!"))
                    break  # Exit verification loop - we're successful!
                
                # ONLY check for verification challenges if we haven't reached success page
                # Check for SPECIFIC error conditions (avoid broad patterns that might match success pages)
                if "deniedsigninrejected" in current_url:
                    raise Exception("❌ Sign-in rejected by Google - Account may be compromised or flagged")
                elif "disabled" in current_url or "suspended" in current_url:
                    raise Exception("❌ Account disabled or suspended - Contact Google support")
                elif "signin/v2/challenge/pwd" not in current_url and "challenge" in current_url:
                    # Ignore normal password challenge URLs, but catch actual verification challenges
                    if "selectchallenge" in current_url or "challenge/selection" in current_url:
                        raise Exception("❌ Google security challenge required - Cannot proceed automatically")
                elif "captcha" in page_source or "recaptcha" in current_url:
                    raise Exception("❌ CAPTCHA verification required - Cannot proceed automatically") 
                elif ("2-step verification is on" in page_source or "two-step verification is on" in page_source) and ("twosv" in current_url or "two-step" in current_url):
                    # Only detect 2FA if we're actually on a 2FA settings page AND it shows as enabled
                    status_queue.put(("error", f"[{email}] ❌ 2-Step Verification already enabled (detected on 2FA settings page)"))
                    status_queue.put(("status", f"[{email}] 🚫 Reason: Account already has 2FA protection - No action needed"))
                    status_queue.put(("status", f"[{email}] 🔄 Closing browser immediately"))
                    raise Exception("❌ Account has existing 2-step verification enabled - Browser will close immediately")
                elif "confirm you're not a robot" in page_source:
                    raise Exception("❌ Google robot verification required - Cannot proceed automatically")
                elif "verify it's you" in page_source and "signin" in current_url:
                    # Only flag if still on signin page, not if on success page
                    raise Exception("❌ Google identity verification required - Cannot proceed automatically")
                
                # Wait before next attempt
                status_queue.put(("status", f"[{email}] Login verification attempt {verification_attempts}/{max_attempts}"))
                time.sleep(8)  # Reduced from 15 to 8 seconds for faster verification
            
            if not login_verified:
                # Final check for specific error messages
                final_url = driver.current_url
                final_source = driver.page_source.lower()
                
                if "signin" in final_url:
                    raise Exception("❌ Still on login page - Password likely incorrect or account locked")
                else:
                    raise Exception(f"❌ Login verification failed after {max_attempts} attempts - Unknown issue")
            
            status_queue.put(("status", f"[{email}] ✅ Login verified successfully"))
            
        except Exception as e:
            # Check for timeout first
            is_timeout, timeout_msg = check_timeout()
            if is_timeout:
                handle_account_failure(timeout_msg)
                try:
                    driver.quit()
                except:
                    pass
                return
            
            # Enhanced login verification error handling
            error_message = str(e)
            handle_account_failure(f"Login verification failed: {error_message}")
            
            # Close browser immediately after login verification failure
            status_queue.put(("status", f"[{email}] 🔄 Closing browser after login verification failure..."))
            try:
                driver.quit()
                status_queue.put(("success", f"[{email}] ✅ Browser closed after login failure"))
            except:
                pass
            return

        # Step 5: Smart 2FA navigation
        # Check timeout before 2FA setup
        is_timeout, timeout_msg = check_timeout()
        if is_timeout:
            handle_account_failure(timeout_msg)
            try:
                driver.quit()
            except:
                pass
            return
            
        if stop_event.is_set():
            status_queue.put(("status", f"[{email}] Stopped - Closing browser..."))
            try:
                driver.quit()
                status_queue.put(("success", f"[{email}] ✅ Browser closed after stop"))
            except:
                pass
            return
            
        status_queue.put(("status", f"[{email}] Smart navigation to 2FA settings"))
        
        # IMMEDIATE 2FA CHECK: Close browser if 2FA is already enabled
        try:
            # First navigate to 2FA page to check status
            driver.get("https://myaccount.google.com/signinoptions/twosv?hl=en")
            finder.wait_for_page_load()
            time.sleep(1)  # Reduced delay for faster 2FA detection
            
            # Check if 2FA is already enabled
            if check_existing_2fa(driver, finder, email, status_queue):
                status_queue.put(("error", f"[{email}] ❌ 2-Step Verification is ALREADY ENABLED on this account"))
                status_queue.put(("status", f"[{email}] 🚫 Reason: Account already has 2FA protection - No action needed"))
                status_queue.put(("status", f"[{email}] 🔄 Closing browser immediately - Moving to next account"))
                
                # Save as failed with specific reason
                save_failed_account(email, password, "Tsv")
                status_queue.put(("update_status", (email, 'Already Protected')))
                
                # Close browser immediately
                try:
                    driver.quit()
                except:
                    pass
                    
                status_queue.put(("completed", email))  # Mark as completed (skip)
                return
                
            status_queue.put(("status", f"[{email}] ✅ 2FA not enabled - Proceeding with setup"))
            
        except Exception as e:
            status_queue.put(("status", f"[{email}] ⚠️ Could not verify 2FA status: {e} - Continuing with setup"))
        
        # Multiple 2FA URLs to try
        twofa_urls = [
            "https://myaccount.google.com/signinoptions/twosv",
            "https://myaccount.google.com/security/signinoptions/twosv",
            "https://accounts.google.com/b/0/signinoptions/twosv?hl=en"
        ]
        
        twofa_loaded = False
        for url in twofa_urls:
            try:
                driver.get(url)
                finder.wait_for_page_load()
                time.sleep(2)
                
                # Verify 2FA page loaded
                if "twosv" in driver.current_url or "two" in driver.page_source.lower():
                    twofa_loaded = True
                    break
            except Exception:
                continue
        
        if not twofa_loaded:
            raise Exception("Could not navigate to 2FA settings page")
        
        status_queue.put(("status", f"[{email}] ✅ 2FA settings page loaded"))
        
        # Step 6: Smart 2FA button detection and activation
        try:
            status_queue.put(("status", f"[{email}] Detecting 2FA setup button"))
            
            # ENGLISH-ONLY 2FA button selectors (PRIMARY - Language forced to English)
            twofa_selectors = [
                # ORIGINAL WORKING SELECTOR
                '//*[@id="yDmH0d"]/c-wiz/div/div[2]/div[2]/c-wiz/div/div[1]/div[4]/div[2]/div/div/div/button/span[4]',
                
                # ENGLISH-FIRST SELECTORS - These should ALWAYS work with language forcing
                '//button[.//span[text()="Turn on"]]',
                '//button[text()="Turn on"]',
                '//span[@jsname="V67aGc" and text()="Turn on"]',
                '//button[contains(text(), "Turn on")]',
                '//span[contains(text(), "Turn on")]',
                '//button[contains(text(), "2-Step") and contains(text(), "Turn on")]',
                
                # STRUCTURAL SELECTORS (no text dependency)
                '//button[@data-value="activate"]',
                '//button[contains(@class, "VfPpkd-LgbsSe") and contains(@class, "VfPpkd-LgbsSe--primary")]',
                '//div[contains(@class, "VfPpkd-RLmnJb")]//button[contains(@class, "VfPpkd-LgbsSe")]',
                '//c-wiz//button[contains(@class, "VfPpkd-LgbsSe")]',
                '//button[contains(@jsaction, "click")]',
                '//button[.//span[@class="VfPpkd-vQzf8d"]]'
            ]
            
            # EMERGENCY FALLBACK - Multi-language (should NOT be needed)
            if len(twofa_selectors) < 15:  # Add fallbacks only if needed
                turn_on_texts = MULTI_LANG_TRANSLATIONS['turn_on']
                for text in turn_on_texts[1:3]:  # Only add first 3 fallback languages
                    twofa_selectors.append(f'//button[.//span[text()="{text}"]]')
            
            twofa_button = finder.find_clickable_element(twofa_selectors, "2FA setup button")
            
            # Smart click with verification
            finder.smart_click(twofa_button, "2FA setup button")
            
            # Verify 2FA setup started
            time.sleep(2)  # Reduced from 3 to 2 seconds for faster verification
            page_source = driver.page_source.lower()
            if "phone" in page_source or "number" in page_source or "verify" in page_source:
                status_queue.put(("status", f"[{email}] ✅ 2FA setup initiated successfully"))
            else:
                status_queue.put(("status", f"[{email}] ⚠️ 2FA button clicked, verifying setup progress..."))
            
        except Exception as e:
            status_queue.put(("error", f"[{email}] 2FA button detection failed: {e}"))
            save_failed_account(email, password, "Tsv")
            
            # Close browser immediately after 2FA failure
            status_queue.put(("status", f"[{email}] 🔄 Closing browser after 2FA setup failure..."))
            try:
                driver.quit()
                status_queue.put(("success", f"[{email}] ✅ Browser closed after 2FA failure"))
            except:
                pass
            return

        # Step 7: Smart phone number entry with intelligent generation
        try:
            if stop_event.is_set():
                status_queue.put(("status", f"[{email}] Stopped - Closing browser..."))
                try:
                    driver.quit()
                    status_queue.put(("success", f"[{email}] ✅ Browser closed after stop"))
                except:
                    pass
                return
                
            status_queue.put(("status", f"[{email}] Smart phone number entry"))
            time.sleep(1)  # Reduced modal load delay for speed
            
            # Enhanced phone input selectors
            phone_selectors = [
                '//input[@type="tel"]',
                '//input[@inputmode="tel"]',
                '//input[contains(@class, "whsOnd") and (@type="tel" or @inputmode="tel")]',
                '//input[@autocomplete="tel"]',
                '//input[@placeholder and contains(translate(@placeholder, "PHONE", "phone"), "phone")]'
            ]
            
            phone_element = finder.find_clickable_element(phone_selectors, "phone input field")
            
            # Intelligent phone number generation (realistic US numbers)
            area_codes = [212, 213, 312, 415, 516, 617, 718, 805, 818, 917, 202, 305, 404, 512, 602, 703, 801, 858, 954, 214, 469, 972, 206, 425, 253, 303, 720, 786, 561, 239]
            area = str(random.choice(area_codes))
            
            # Avoid reserved prefixes (like 555, 911, etc.)
            valid_prefixes = [x for x in range(200, 1000) if x not in [555, 911, 411, 611, 811]]
            prefix = str(random.choice(valid_prefixes))
            
            line = str(random.randint(1000, 9999))
            
            # Try different formats based on field detection
            phone_formats = [
                f"({area}) {prefix}-{line}",  # US format with parentheses
                f"{area}-{prefix}-{line}",     # US format with dashes
                f"+1{area}{prefix}{line}",     # International format
                f"{area}{prefix}{line}"        # Plain format
            ]
            
            phone_entered = False
            for phone_format in phone_formats:
                try:
                    finder.smart_input(phone_element, phone_format, "phone number field")
                    
                    # Verify phone number was accepted
                    entered_value = driver.execute_script("return arguments[0].value;", phone_element)
                    if len(entered_value) >= 10:  # Minimum valid phone length
                        phone_number = phone_format
                        phone_entered = True
                        break
                    else:
                        # Clear and try next format
                        phone_element.clear()
                except Exception:
                    continue
            
            if not phone_entered:
                raise Exception("Could not enter phone number in any format")
            
            status_queue.put(("status", f"[{email}] ✅ Phone number entered: {phone_number}"))

            # Smart Next button clicking in phone modal with comprehensive selectors
            status_queue.put(("status", f"[{email}] Looking for Next button in phone modal"))
            
            # ENGLISH-ONLY Next button selectors (PRIMARY - Language forced to English)
            next_selectors = [
                # ENGLISH-FIRST SELECTORS - These should ALWAYS work with language forcing
                '//button[.//span[@jsname="V67aGc" and text()="Next"]]',
                '//button[.//span[text()="Next"]]',
                '//button[text()="Next"]',
                '//span[@jsname="V67aGc" and text()="Next"]',
                '//button[contains(text(), "Next")]',
                '//span[contains(text(), "Next")]',
                
                # MODAL-SPECIFIC ENGLISH SELECTORS
                '//div[@role="dialog"]//button[.//span[text()="Next"]]',
                '//div[@role="dialog"]//button[text()="Next"]',
                '//div[@role="dialog"]//span[text()="Next"]',
                
                # STRUCTURAL SELECTORS (no text dependency)
                '//button[@data-mdc-dialog-action="next"]',
                '//div[@role="dialog"]//button[contains(@class, "VfPpkd-LgbsSe--primary")]',
                '//div[@role="dialog"]//button[last()]',
                '//button[.//span[@jsname="V67aGc"]]'
            ]
            
            # EMERGENCY FALLBACK - Multi-language (should NOT be needed with language forcing)
            if len(next_selectors) < 20:  # Add fallbacks only if needed
                next_texts = MULTI_LANG_TRANSLATIONS['next']
                for text in next_texts[1:5]:  # Only add first 5 fallback languages
                    next_selectors.append(f'//button[.//span[text()="{text}"]]')
            
            next_button_found = None
            for i, selector in enumerate(next_selectors):
                try:
                    # Use smart finder with shorter timeout for each attempt
                    temp_finder = SmartElementFinder(driver, 3)
                    next_button_found = temp_finder.find_clickable_element([selector], f"Next button (attempt {i+1})")
                    status_queue.put(("status", f"[{email}] Found Next button with selector {i+1}"))
                    break
                except Exception as e:
                    continue
            
            if next_button_found:
                try:
                    finder.smart_click(next_button_found, "Next button in phone modal")
                    status_queue.put(("status", f"[{email}] ✅ Successfully clicked Next button - looking for phone confirmation"))
                    time.sleep(2)  # Reduced from 3 to 2 seconds for faster modal transitions
                    
                    # Handle "Confirm your phone number" modal with Save button
                    status_queue.put(("status", f"[{email}] Looking for Save button in phone confirmation modal"))
                    
                    # ENGLISH-ONLY Save button selectors (PRIMARY - Language forced to English)
                    save_selectors = [
                        # ENGLISH-FIRST SELECTORS - These should ALWAYS work with language forcing
                        '//button[.//span[text()="Save"]]',
                        '//button[text()="Save"]',
                        '//span[@jsname="V67aGc" and text()="Save"]',
                        '//button[contains(text(), "Save")]',
                        '//span[contains(text(), "Save")]',
                        
                        # SPECIFIC SAVE BUTTON WITH DATA ATTRIBUTES
                        '//button[@data-mdc-dialog-action="x8hlje"]',
                        '//button[@data-mdc-dialog-action="x8hlje" and @aria-label="Save phone number"]',
                        
                        # MODAL-SPECIFIC ENGLISH SELECTORS
                        '//div[@role="dialog"]//button[.//span[text()="Save"]]',
                        '//div[@role="dialog"]//button[text()="Save"]',
                        '//div[@aria-modal="true"]//button[.//span[text()="Save"]]',
                        
                        # STRUCTURAL SELECTORS (no text dependency)
                        '//button[contains(@data-mdc-dialog-action, "save")]',
                        '//div[@role="dialog"]//button[not(@disabled) and not(contains(@style, "display: none"))][last()]',
                        '//button[.//span[@jsname="V67aGc"]]'
                    ]
                    
                    # EMERGENCY FALLBACK - Multi-language (should NOT be needed)
                    if len(save_selectors) < 15:  # Add fallbacks only if needed
                        save_texts = MULTI_LANG_TRANSLATIONS['save']
                        for text in save_texts[1:3]:  # Only add first 3 fallback languages
                            save_selectors.append(f'//button[.//span[text()="{text}"]]')
                    
                    save_button_found = None
                    for i, selector in enumerate(save_selectors):
                        try:
                            # Use smart finder with moderate timeout for each attempt
                            temp_finder = SmartElementFinder(driver, 5)
                            save_button_found = temp_finder.find_clickable_element([selector], f"Save button (attempt {i+1})")
                            status_queue.put(("status", f"[{email}] Found Save button with selector {i+1}"))
                            break
                        except Exception as e:
                            continue
                    
                    if save_button_found:
                        try:
                            finder.smart_click(save_button_found, "Save button in phone confirmation modal")
                            status_queue.put(("status", f"[{email}] ✅ Successfully clicked Save button - phone number confirmed"))
                            time.sleep(2)  # Reduced from 3 to 2 seconds for faster step progression
                        except Exception as e:
                            status_queue.put(("status", f"[{email}] Save button click failed but continuing: {e}"))
                    else:
                        status_queue.put(("status", f"[{email}] Save button not found - checking for auto-progression"))
                        
                        # Debug: Log available buttons in confirmation modal
                        try:
                            confirmation_buttons = driver.find_elements(By.XPATH, '//div[@role="dialog"]//button')
                            status_queue.put(("status", f"[{email}] DEBUG: Found {len(confirmation_buttons)} buttons in confirmation modal"))
                            
                            for i, btn in enumerate(confirmation_buttons[:5]):
                                try:
                                    btn_text = btn.get_attribute("textContent") or btn.get_attribute("innerText") or "No text"
                                    btn_action = btn.get_attribute("data-mdc-dialog-action") or "No action"
                                    btn_disabled = btn.get_attribute("disabled") or "Not disabled"
                                    btn_style = btn.get_attribute("style") or "No inline style"
                                    status_queue.put(("status", f"[{email}] DEBUG: Button {i+1}: '{btn_text[:30]}' | Action: '{btn_action}' | Disabled: '{btn_disabled}' | Style: '{btn_style[:50]}'"))
                                except:
                                    pass
                        except:
                            pass
                    
                except Exception as e:
                    status_queue.put(("error", f"[{email}] Phone confirmation handling failed: {e}"))
                    raise Exception(f"Phone confirmation failed: {e}")
            else:
                status_queue.put(("error", f"[{email}] Could not find Next button with any selector"))
                
                # Debug: Log available buttons for troubleshooting
                try:
                    all_buttons = driver.find_elements(By.TAG_NAME, "button")
                    status_queue.put(("status", f"[{email}] DEBUG: Found {len(all_buttons)} buttons on page"))
                    
                    modal_buttons = driver.find_elements(By.XPATH, '//div[@role="dialog"]//button')
                    status_queue.put(("status", f"[{email}] DEBUG: Found {len(modal_buttons)} buttons in modal"))
                    
                    for i, btn in enumerate(modal_buttons[:3]):  # Show first 3 modal buttons
                        try:
                            btn_text = btn.get_attribute("textContent") or btn.get_attribute("innerText") or "No text"
                            btn_class = btn.get_attribute("class") or "No class"
                            status_queue.put(("status", f"[{email}] DEBUG: Modal Button {i+1}: '{btn_text[:50]}' | Class: '{btn_class[:50]}'"))
                        except:
                            pass
                except:
                    pass
                
                raise Exception("Could not find Next button with any selector")

        except Exception as e:
            status_queue.put(("error", f"[{email}] Phone number entry and confirmation failed: {e}"))
            save_failed_account(email, password, f"Phone number entry failed: {e}")
            
            # Close browser immediately after phone number failure
            status_queue.put(("status", f"[{email}] 🔄 Closing browser after phone number failure..."))
            try:
                driver.quit()
                status_queue.put(("success", f"[{email}] ✅ Browser closed after phone failure"))
            except:
                pass
            return

        # Skip "You're now protected" modal - Direct navigation to app passwords
        if stop_event.is_set():
            status_queue.put(("status", f"[{email}] Stopped - Closing browser..."))
            try:
                driver.quit()
                status_queue.put(("success", f"[{email}] ✅ Browser closed after stop"))
            except:
                pass
            return
            
        status_queue.put(("status", f"[{email}] Skipping 2FA completion modal - navigating directly to App Passwords"))
        time.sleep(0.5)  # Brief pause - immediate processing
        
        # Direct navigation to app passwords page (saves time)
        try:
            status_queue.put(("status", f"[{email}] Smart navigation to App Passwords page"))
            
            # Multiple app password URLs to try
            app_password_urls = [
                "https://myaccount.google.com/apppasswords",
                "https://myaccount.google.com/security/signinoptions/twosv/apppasswords",
                "https://accounts.google.com/b/0/apppasswords?hl=en"
            ]
            
            app_passwords_loaded = False
            for url in app_password_urls:
                try:
                    driver.get(url)
                    finder.wait_for_page_load()
                    time.sleep(2)
                    
                    # Verify app passwords page loaded
                    current_url = driver.current_url
                    page_source = driver.page_source.lower()
                    if "apppasswords" in current_url or "app password" in page_source or "application password" in page_source:
                        app_passwords_loaded = True
                        status_queue.put(("status", f"[{email}] ✅ App Passwords page loaded successfully"))
                        break
                except Exception:
                    continue
            
            if not app_passwords_loaded:
                raise Exception("Could not navigate to App Passwords page")
            
        except Exception as e:
            status_queue.put(("error", f"[{email}] App Passwords navigation failed: {e}"))
            save_failed_account(email, password, f"App Passwords navigation failed: {e}")
            
            # Close browser immediately after navigation failure
            status_queue.put(("status", f"[{email}] 🔄 Closing browser after navigation failure..."))
            try:
                driver.quit()
                status_queue.put(("success", f"[{email}] ✅ Browser closed after navigation failure"))
            except:
                pass
            return

        # Step 8: Create app password
        if stop_event.is_set():
            status_queue.put(("status", f"[{email}] Stopped - Browser left open"))
            return
            
        status_queue.put(("status", f"[{email}] Creating app password"))
        try:
            app_input = finder.wait.until(EC.visibility_of_element_located((By.XPATH, '//input[@id="i4" and @jsname="YPqjbf"]')))
            app_input.clear()
            app_input.send_keys("AutomationApp")

            # Generate ENGLISH-FIRST selectors since we're forcing English language
            # Primary English selectors (more reliable with language forcing)
            create_selectors = [
                '//button[.//span[@jsname="V67aGc" and (text()="Create" or contains(text(), "Create"))]]',
                '//button[contains(text(), "Create") or .//span[contains(text(), "Create")]]',
                '//button[@data-action="create"]',
                '//button[contains(@class, "VfPpkd-LgbsSe") and contains(@class, "VfPpkd-LgbsSe--primary")]',
                '//button[.//span[@jsname="V67aGc"]]'  # Generic button with jsname span
            ]
            
            # Multi-language fallback (in case language forcing fails)
            create_texts = MULTI_LANG_TRANSLATIONS['create']
            create_text_conditions = []
            for text in create_texts:
                create_text_conditions.extend([
                    f'text()="{text}"',
                    f'contains(text(), "{text}")'
                ])
            
            fallback_condition = ' or '.join(create_text_conditions)
            create_selectors.append(f'//button[{fallback_condition}]')
            
            create_clicked = False
            for selector in create_selectors:
                try:
                    create_btn = finder.wait.until(EC.element_to_be_clickable((By.XPATH, selector)))
                    driver.execute_script("arguments[0].scrollIntoView({block: 'center'});", create_btn)
                    time.sleep(1)
                    try:
                        create_btn.click()
                    except Exception:
                        driver.execute_script("arguments[0].click();", create_btn)
                    status_queue.put(("status", f"[{email}] ✅ App password created"))
                    create_clicked = True
                    break
                except Exception:
                    continue
            
            if not create_clicked:
                raise Exception("Could not find Create button with any selector")

            # Step 9: Collect the generated app password from the modal
            backup_codes = []
            try:
                modal = finder.wait.until(EC.visibility_of_element_located((By.XPATH, '//div[@class="uW2Fw-P5QLlc" and @aria-modal="true"]')))
                strong = modal.find_element(By.XPATH, './/strong[@class="v2CTKd KaSAf"]')
                
                # METHOD 1: Try to get the complete text with spaces from the strong element
                app_password_full = strong.text.strip()
                status_queue.put(("status", f"[{email}] 🔍 Full strong element text: '{app_password_full}'"))
                
                # METHOD 2: Try individual spans with spaces between them  
                spans = strong.find_elements(By.TAG_NAME, 'span')
                if len(spans) >= 4:  # Google typically shows 4 groups
                    # Join spans with spaces to match Google's format: "abcd efgh ijkl mnop"
                    span_texts = [span.text.strip() for span in spans if span.text.strip()]
                    app_password_spans = ' '.join(span_texts)
                    status_queue.put(("status", f"[{email}] 🔍 Spans with spaces: '{app_password_spans}'"))
                else:
                    app_password_spans = ''.join([span.text for span in spans])
                    status_queue.put(("status", f"[{email}] 🔍 Spans joined: '{app_password_spans}'"))
                
                # Use the version that has spaces (typically the full text or spaced spans)
                if ' ' in app_password_full and len(app_password_full) > 16:
                    app_password = app_password_full
                    status_queue.put(("status", f"[{email}] ✅ Using full text with spaces"))
                elif ' ' in app_password_spans and len(app_password_spans) > 16:
                    app_password = app_password_spans  
                    status_queue.put(("status", f"[{email}] ✅ Using spans with spaces"))
                else:
                    # Fallback: add spaces manually in standard format (4 groups of 4)
                    app_password_clean = ''.join([span.text for span in spans])
                    if len(app_password_clean) == 16:  # Standard 16-character format
                        app_password = f"{app_password_clean[0:4]} {app_password_clean[4:8]} {app_password_clean[8:12]} {app_password_clean[12:16]}"
                        status_queue.put(("status", f"[{email}] ✅ Formatted with standard spacing"))
                    else:
                        app_password = app_password_clean
                        status_queue.put(("status", f"[{email}] ⚠️ Using without spaces (unusual length: {len(app_password_clean)})"))
                
                status_queue.put(("status", f"[{email}] 🔑 Final app password: '{app_password}'"))
                
                # Collect backup codes after getting app password
                backup_codes = collect_backup_codes(driver, finder, email, status_queue)
                
                # IMMEDIATE SAVE - Save app password and backup codes together RIGHT NOW
                status_queue.put(("status", f"[{email}] 💾 Saving app password and backup codes to CSV immediately..."))
                status_queue.put(("status", f"[{email}] 🔍 App password to save: '{app_password}' (length: {len(app_password)})"))
                status_queue.put(("status", f"[{email}] 🔍 Backup codes to save: {backup_codes}"))
                
                # STRICT SUCCESS VALIDATION - Only save if ALL criteria are met
                success_criteria = {
                    'app_password_valid': app_password and len(app_password.strip().replace(' ', '')) >= 16,
                    'backup_codes_sufficient': backup_codes and len(backup_codes) >= 2,
                    'phone_setup_completed': True  # We assume phone was set up if we got this far
                }
                
                # Validate each component
                validation_messages = []
                if not success_criteria['app_password_valid']:
                    validation_messages.append("❌ App password invalid or too short")
                if not success_criteria['backup_codes_sufficient']:
                    validation_messages.append(f"❌ Insufficient backup codes ({len(backup_codes) if backup_codes else 0}/2 minimum)")
                
                # Only proceed if ALL criteria are met
                if all(success_criteria.values()):
                    save_result = save_app_password(email, password, app_password, backup_codes)
                    
                    # Confirm immediate save success with details
                    backup_count = len(backup_codes) if backup_codes else 0
                    status_queue.put(("success", f"[{email}] ✅ COMPLETE SUCCESS: App password ({len(app_password)} chars) + {backup_count} backup codes saved"))
                    status_queue.put(("success", f"[{email}] 📝 File: successful_accounts.csv"))
                    status_queue.put(("update_status", (email, 'Complete Success')))
                else:
                    # Report what failed validation
                    error_msg = f"❌ INCOMPLETE SETUP: {'; '.join(validation_messages)}"
                    status_queue.put(("error", f"[{email}] {error_msg}"))
                    save_failed_account(email, password, error_msg)
                    status_queue.put(("update_status", (email, 'Incomplete Setup')))
                
                # Close browser immediately and proceed to next
                status_queue.put(("status", f"[{email}] 🔄 Closing browser and proceeding to next account..."))
                try:
                    driver.quit()
                    status_queue.put(("success", f"[{email}] ✅ Browser closed successfully"))
                except:
                    pass
                
            except Exception as e:
                status_queue.put(("error", f"[{email}] Could not extract app password: {e}"))
                save_failed_account(email, password, f"Could not extract app password: {e}")
                status_queue.put(("update_status", (email, 'Failed')))
                
                # Close browser immediately after failure and proceed to next
                status_queue.put(("status", f"[{email}] 🔄 Closing browser after failure and proceeding to next account..."))
                try:
                    driver.quit()
                    status_queue.put(("success", f"[{email}] ✅ Browser closed after failure"))
                except:
                    pass

        except Exception as e:
            status_queue.put(("error", f"[{email}] App password creation failed: {e}"))
            save_failed_account(email, password, f"App password creation failed: {e}")
            
            # Close browser immediately after app password failure
            status_queue.put(("status", f"[{email}] 🔄 Closing browser after app password failure..."))
            try:
                driver.quit()
                status_queue.put(("success", f"[{email}] ✅ Browser closed after app password failure"))
            except:
                pass

        # Mark automation as completed successfully and close browser
        status_queue.put(("status", f"[{email}] ✅ Automation completed successfully - Closing browser..."))
        try:
            driver.quit()
            status_queue.put(("success", f"[{email}] ✅ Browser closed after successful completion"))
        except:
            pass
        status_queue.put(("completed", email))

    except Exception as e:
        # Enhanced WebDriver error detection and handling
        error_message = str(e).lower()
        user_friendly_error = ""
        
        # Detect specific WebDriver errors and provide user-friendly messages
        if "invalid session id" in error_message or isinstance(e, InvalidSessionIdException):
            user_friendly_error = "🔧 WEBDRIVER CRASH: Browser session crashed unexpectedly - This is usually due to Chrome/system instability"
            status_queue.put(("error", f"[{email}] {user_friendly_error}"))
            status_queue.put(("status", f"[{email}] 💡 Recommendation: Restart the application and try again"))
            save_failed_account(email, password, "WebDriver session crashed (invalid session id) - Browser instability")
        elif "session deleted" in error_message or "chrome not reachable" in error_message:
            user_friendly_error = "🔧 BROWSER TERMINATED: Chrome browser was closed or crashed during automation"
            status_queue.put(("error", f"[{email}] {user_friendly_error}"))
            status_queue.put(("status", f"[{email}] 💡 Recommendation: Let the automation complete without manually closing browsers"))
            save_failed_account(email, password, "Browser was terminated or crashed during automation")
        elif "connection refused" in error_message or "connection reset" in error_message:
            user_friendly_error = "🌐 CONNECTION ERROR: Network or browser connection failed"
            status_queue.put(("error", f"[{email}] {user_friendly_error}"))
            status_queue.put(("status", f"[{email}] 💡 Recommendation: Check your internet connection and try again"))
            save_failed_account(email, password, f"Network connection error: {str(e)[:100]}")
        elif "timeout" in error_message:
            user_friendly_error = "⏱️ TIMEOUT ERROR: Page took too long to load or respond"
            status_queue.put(("error", f"[{email}] {user_friendly_error}"))
            status_queue.put(("status", f"[{email}] � Recommendation: Try again with a better internet connection"))
            save_failed_account(email, password, f"Timeout error: {str(e)[:100]}")
        else:
            # Generic automation failure
            user_friendly_error = f"❌ AUTOMATION ERROR: {str(e)[:100]}..."
            status_queue.put(("error", f"[{email}] {user_friendly_error}"))
            save_failed_account(email, password, f"Automation failed: {e}")
        
        # Close browser immediately after any error (with enhanced error handling)
        status_queue.put(("status", f"[{email}] 🔄 Attempting to close browser after error..."))
        try:
            if driver is not None:
                driver.quit()
                status_queue.put(("success", f"[{email}] ✅ Browser closed after error"))
        except (InvalidSessionIdException, WebDriverException):
            # Browser already crashed/closed
            status_queue.put(("success", f"[{email}] ✅ Browser was already closed (crash detected)"))
        except Exception as cleanup_error:
            status_queue.put(("status", f"[{email}] ⚠️ Browser cleanup failed: {cleanup_error}"))
    finally:
        # CRITICAL: Always close browser, even on unexpected errors - Enhanced WebDriver crash handling
        try:
            if 'driver' in locals() and driver is not None:
                driver.quit()
                status_queue.put(("success", f"[{email}] ✅ Browser cleanup completed"))
        except (InvalidSessionIdException, WebDriverException):
            # Browser session already crashed/terminated - this is expected
            status_queue.put(("success", f"[{email}] ✅ Browser cleanup skipped (session already terminated)"))
        except Exception as final_cleanup_error:
            # Any other cleanup error - log but don't fail
            status_queue.put(("status", f"[{email}] ⚠️ Final browser cleanup error: {str(final_cleanup_error)[:50]}..."))
            
        # 🛡️ ENHANCED CHROME PROCESS CLEANUP FOR EXE STABILITY 🛡️
        # Clean up any orphaned Chrome processes to prevent EXE crashes
        try:
            import psutil
            chrome_processes = []
            for proc in psutil.process_iter(['pid', 'name', 'cmdline']):
                if (proc.info['name'] and 'chrome' in proc.info['name'].lower() and 
                    proc.info['cmdline'] and temp_dir and temp_dir.replace('\\', '/') in ' '.join(proc.info['cmdline'])):
                    chrome_processes.append(proc)
            
            if chrome_processes:
                status_queue.put(("status", f"[{email}] 🧹 Cleaning up {len(chrome_processes)} Chrome processes for EXE stability"))
                for proc in chrome_processes:
                    try:
                        proc.terminate()
                        proc.wait(timeout=3)  # Wait up to 3 seconds for graceful termination
                    except (psutil.NoSuchProcess, psutil.TimeoutExpired):
                        try:
                            proc.kill()  # Force kill if termination didn't work
                        except psutil.NoSuchProcess:
                            pass  # Process already gone
                    except Exception:
                        pass  # Continue cleanup even if one process fails
                        
        except ImportError:
            # psutil not available, basic cleanup
            status_queue.put(("status", f"[{email}] 🧹 Basic Chrome cleanup (psutil not available)"))
        except Exception:
            # Any other error during Chrome cleanup
            pass

        # Clean up temporary directory
        if temp_dir and os.path.exists(temp_dir):
            try:
                shutil.rmtree(temp_dir, ignore_errors=True)
                status_queue.put(("status", f"[{email}] 🗂️ Temporary directory cleaned up"))
            except Exception:
                pass

class GoogleAutomationGUI:
    def __init__(self, root):
        # CRITICAL: IMMEDIATE EXPIRY CHECK - TERMINATE IF EXPIRED
        _check_license_expiry_immediate()
        
        # CRITICAL: Comprehensive license validation at GUI initialization
        if not LICENSE_ENFORCEMENT_ACTIVE:
            safe_print("SECURITY VIOLATION: License enforcement disabled!")
            sys.exit(1)
        
        # 🔒 ENHANCED SECURITY: Check for any bypass files before proceeding
        bypass_files = ["master_access.key", "bypass.key", "unlock.key", "override.key", "admin.key"]
        for bypass_file in bypass_files:
            if os.path.exists(bypass_file):
                messagebox.showerror("Security Error", "Unauthorized bypass detected. Application will exit.")
                sys.exit(1)
        
        if not _0x4c1c3ns3_ch3ck():
            messagebox.showerror("License Error", "Invalid or expired license. Please restart the application.")
            sys.exit(1)
        
        if not _0x5d2e4f1a_v4l1d4t3():
            messagebox.showerror("Security Error", "Security validation failed. Application will exit.")
            sys.exit(1)
            
        if not _0x7f3a9b2c_s3cur1ty():
            messagebox.showerror("License Error", "License integrity check failed. Application will exit.")
            sys.exit(1)
        
        # Additional integrity check
        _verify_app_integrity()
        
        self.root = root
        self.root.title("Google Account Automation Tool")
        self.root.configure(bg='#f0f0f0')
        
        # 🖥️ GUI PRESERVATION SYSTEM - Prevents interface from disappearing due to Chrome GPU errors
        self.setup_gui_preservation()
        
        # Calculate center position BEFORE setting geometry
        window_width = 800
        window_height = 600
        screen_width = self.root.winfo_screenwidth()
        screen_height = self.root.winfo_screenheight()
        x = (screen_width - window_width) // 2
        y = (screen_height - window_height) // 2
        
        # Set geometry with center position immediately
        self.root.geometry(f"{window_width}x{window_height}+{x}+{y}")
        
        self.accounts = []
        self.worker_threads = []
        self.status_queue = queue.Queue()
        self.stop_event = threading.Event()
        self.automation_running = False
        
        self.setup_ui()
        self.setup_menu_bar()
        self.check_queue()
        
        # Display license info on startup (after UI is created)
        self.root.after(100, self.show_license_status)
        
        # Start periodic license validation (every 5 minutes)
        self.start_periodic_license_check()
        
    def setup_gui_preservation(self):
        """Setup GUI preservation to prevent interface from disappearing due to Chrome GPU context failures"""
        try:
            # Set up window state tracking
            self.user_minimized = False
            self.last_window_state = 'normal'
            
            # Bind window state change event
            self.root.bind('<Map>', self.on_window_map)
            self.root.bind('<Unmap>', self.on_window_unmap)
            
            # Smart GUI preservation that respects user actions
            def smart_gui_preservation():
                try:
                    if self.root.winfo_exists():
                        current_state = self.root.state()
                        
                        # Only restore if window disappeared unexpectedly (not user minimized)
                        if current_state == 'withdrawn' and not self.user_minimized:
                            self.root.deiconify()  # Only restore if not intentionally minimized
                        
                        # Keep GUI responsive without forcing visibility
                        self.root.update_idletasks()
                        self.root.after(3000, smart_gui_preservation)  # Check every 3 seconds
                except Exception:
                    pass  # GUI was destroyed or error occurred, stop preservation
            
            # Start smart preservation system
            self.root.after(3000, smart_gui_preservation)
            
            # Handle window close properly
            self.root.protocol("WM_DELETE_WINDOW", self.on_closing)
            
        except Exception as e:
            print(f"GUI preservation setup failed: {e}")
    
    def on_window_map(self, event):
        """Called when window is mapped (shown)"""
        if event.widget == self.root:
            self.user_minimized = False
            self.last_window_state = 'normal'
    
    def on_window_unmap(self, event):
        """Called when window is unmapped (hidden/minimized)"""
        if event.widget == self.root:
            # Check if this is user-initiated minimization
            try:
                current_state = self.root.state()
                if current_state == 'iconic':
                    self.user_minimized = True
                    self.last_window_state = 'iconic'
            except Exception:
                pass
    
    def on_closing(self):
        """Handle window closing properly"""
        try:
            # Stop all automation threads
            self.stop_event.set()
            
            # Wait briefly for threads to stop
            for thread in self.worker_threads:
                if thread.is_alive():
                    thread.join(timeout=1)
            
            # Destroy the window
            self.root.destroy()
        except Exception:
            # Force quit if graceful shutdown fails
            import os
            os._exit(0)
    
    def setup_menu_bar(self):
        """Setup menu bar with Help and License options"""
        menubar = tk.Menu(self.root)
        self.root.config(menu=menubar)
        
        # File menu
        file_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="File", menu=file_menu)
        file_menu.add_command(label="Load CSV", command=self.browse_file)
        file_menu.add_separator()
        file_menu.add_command(label="Exit", command=self.root.quit)
        
        # License menu
        license_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="License", menu=license_menu)
        license_menu.add_command(label="License Information", command=self.show_license_info)
        license_menu.add_command(label="Check License Validity", command=self.check_license_validity)
        license_menu.add_command(label="Reactivate License", command=self.reactivate_license)
        
        # Help menu
        help_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="Help", menu=help_menu)
        help_menu.add_command(label="User Guide", command=self.show_user_guide)
        help_menu.add_command(label="Development Info", command=self.show_dev_info)
        help_menu.add_separator()
        help_menu.add_command(label="About", command=self.show_about)
    
    def setup_ui(self):
        # Title
        title_frame = tk.Frame(self.root, bg='#f0f0f0')
        title_frame.pack(pady=10)
        
        title_label = tk.Label(title_frame, text="🔐 Google Account Automation Tool", 
                              font=('Arial', 16, 'bold'), bg='#f0f0f0', fg='#2c3e50')
        title_label.pack()
        
        subtitle_label = tk.Label(title_frame, text="Automate 2FA setup and app password generation", 
                                 font=('Arial', 10), bg='#f0f0f0', fg='#7f8c8d')
        subtitle_label.pack()

        # Max concurrent browsers setting
        concurrency_frame = tk.Frame(self.root, bg='#f0f0f0')
        concurrency_frame.pack(pady=(0, 10))
        tk.Label(concurrency_frame, text="Max concurrent browsers:", font=('Arial', 10), bg='#f0f0f0').pack(side='left')
        self.max_concurrent_var = tk.IntVar(value=2)
        self.max_concurrent_spin = tk.Spinbox(concurrency_frame, from_=1, to=20, width=5, textvariable=self.max_concurrent_var, font=('Arial', 10))
        self.max_concurrent_spin.pack(side='left', padx=(5, 0))
        
        # File selection frame
        file_frame = tk.LabelFrame(self.root, text="📁 Account File", font=('Arial', 10, 'bold'), 
                                  bg='#f0f0f0', fg='#2c3e50')
        file_frame.pack(fill='x', padx=20, pady=10)
        
        file_button_frame = tk.Frame(file_frame, bg='#f0f0f0')
        file_button_frame.pack(fill='x', padx=10, pady=10)
        
        self.file_path_var = tk.StringVar()
        self.file_path_entry = tk.Entry(file_button_frame, textvariable=self.file_path_var, 
                                       font=('Arial', 10), state='readonly')
        self.file_path_entry.pack(side='left', fill='x', expand=True, padx=(0, 10))
        
        browse_btn = tk.Button(file_button_frame, text="Browse CSV", command=self.browse_file,
                              bg='#3498db', fg='white', font=('Arial', 10, 'bold'),
                              relief='flat', padx=20)
        browse_btn.pack(side='right')
        
        # Accounts display
        accounts_frame = tk.LabelFrame(self.root, text="👥 Loaded Accounts", font=('Arial', 10, 'bold'),
                                      bg='#f0f0f0', fg='#2c3e50')
        accounts_frame.pack(fill='both', expand=True, padx=20, pady=10)
        
        # Treeview for accounts
        self.accounts_tree = ttk.Treeview(accounts_frame, columns=('Email', 'Status'), show='headings', height=6)
        self.accounts_tree.heading('Email', text='Email Address')
        self.accounts_tree.heading('Status', text='Status')
        self.accounts_tree.column('Email', width=300)
        self.accounts_tree.column('Status', width=200)
        
        tree_scroll = ttk.Scrollbar(accounts_frame, orient='vertical', command=self.accounts_tree.yview)
        self.accounts_tree.configure(yscrollcommand=tree_scroll.set)
        
        self.accounts_tree.pack(side='left', fill='both', expand=True, padx=(10, 0), pady=10)
        tree_scroll.pack(side='right', fill='y', padx=(0, 10), pady=10)
        
        # Progress frame
        progress_frame = tk.LabelFrame(self.root, text="📊 Progress", font=('Arial', 10, 'bold'),
                                      bg='#f0f0f0', fg='#2c3e50')
        progress_frame.pack(fill='x', padx=20, pady=10)
        
        self.progress_var = tk.DoubleVar()
        self.progress_bar = ttk.Progressbar(progress_frame, variable=self.progress_var, 
                                           maximum=100, style='TProgressbar')
        self.progress_bar.pack(fill='x', padx=10, pady=(10, 5))
        
        self.progress_label = tk.Label(progress_frame, text="Ready to start", 
                                      font=('Arial', 10), bg='#f0f0f0', fg='#2c3e50')
        self.progress_label.pack(pady=(0, 10))
        
        # Control buttons
        button_frame = tk.Frame(self.root, bg='#f0f0f0')
        button_frame.pack(fill='x', padx=20, pady=10)
        
        self.start_btn = tk.Button(button_frame, text="🚀 Start Automation", 
                                  command=self.start_automation,
                                  bg='#27ae60', fg='white', font=('Arial', 12, 'bold'),
                                  relief='flat', padx=30, pady=10)
        self.start_btn.pack(side='left', padx=(0, 10))
        
        self.stop_btn = tk.Button(button_frame, text="⏹️ Stop", 
                                 command=self.stop_automation,
                                 bg='#e74c3c', fg='white', font=('Arial', 12, 'bold'),
                                 relief='flat', padx=30, pady=10, state='disabled')
        self.stop_btn.pack(side='left', padx=(0, 10))
        
        clear_btn = tk.Button(button_frame, text="🗑️ Clear", 
                             command=self.clear_accounts,
                             bg='#95a5a6', fg='white', font=('Arial', 12, 'bold'),
                             relief='flat', padx=30, pady=10)
        clear_btn.pack(side='left')
        
        # Status log frame
        log_frame = tk.LabelFrame(self.root, text="📋 Status Log", font=('Arial', 10, 'bold'),
                                 bg='#f0f0f0', fg='#2c3e50')
        log_frame.pack(fill='both', expand=True, padx=20, pady=(0, 20))
        
        self.log_text = scrolledtext.ScrolledText(log_frame, height=8, font=('Consolas', 9),
                                                 bg='#2c3e50', fg='#ecf0f1', insertbackground='white')
        self.log_text.pack(fill='both', expand=True, padx=10, pady=10)
        
        # Add initial message
        self.log_message("Welcome to Google Account Automation Tool!")
        self.log_message("Please select a CSV file with your accounts to begin.")
        self.log_message("ℹ️ Note: Browser windows will remain OPEN for manual review/intervention.")
        self.log_message("   You can manually complete any failed steps in the open browsers.")
    
    def browse_file(self):
        # CRITICAL: Check expiry before allowing file operations
        _check_license_expiry_immediate()
        
        file_path = filedialog.askopenfilename(
            title="Select Accounts CSV File",
            filetypes=[("CSV files", "*.csv"), ("All files", "*.*")]
        )
        
        if file_path:
            self.file_path_var.set(file_path)
            self.load_accounts(file_path)
    
    def load_accounts(self, file_path):
        try:
            self.accounts = []
            # Clear existing entries
            for item in self.accounts_tree.get_children():
                self.accounts_tree.delete(item)
            
            with open(file_path, 'r', newline='', encoding='utf-8') as file:
                reader = csv.DictReader(file)
                for row in reader:
                    email = row.get('email', '').strip()
                    password = row.get('password', '').strip()
                    if email and password:
                        self.accounts.append({'email': email, 'password': password})
                        self.accounts_tree.insert('', 'end', values=(email, 'Ready'))
            
            self.log_message(f"✅ Loaded {len(self.accounts)} accounts from {os.path.basename(file_path)}")
            
            if self.accounts:
                self.start_btn.config(state='normal')
            else:
                messagebox.showwarning("No Accounts", "No valid accounts found in the selected file.")
                
        except Exception as e:
            messagebox.showerror("Error", f"Failed to load accounts: {e}")
            self.log_message(f"❌ Error loading accounts: {e}")
    
    def start_automation(self):
        # 🚨 IMMEDIATE REVOCATION CHECK - ADMIN CAN STOP AUTOMATION INSTANTLY
        _validate_license_for_operation("automation_start")
        
        # CRITICAL: IMMEDIATE EXPIRY CHECK - NO AUTOMATION IF EXPIRED
        _check_license_expiry_immediate()
        
        # CRITICAL: Comprehensive license check before starting automation
        if not LICENSE_ENFORCEMENT_ACTIVE:
            messagebox.showerror("Security Error", "License enforcement has been tampered with. Application will exit.")
            sys.exit(1)
            
        if not _0x4c1c3ns3_ch3ck():
            messagebox.showerror("License Error", "License validation failed. Please restart the application.")
            sys.exit(1)
            
        if not _0x5d2e4f1a_v4l1d4t3():
            messagebox.showerror("Security Error", "Security validation failed. Application will exit.")
            sys.exit(1)
            
        if not _0x7f3a9b2c_s3cur1ty():
            messagebox.showerror("License Error", "License integrity compromised. Application will exit.")
            sys.exit(1)
        
        # Additional runtime verification
        _verify_app_integrity()
        
        # Verify license is still valid at automation start
        hardware_id = get_hardware_id()
        valid, message = validate_license_key("", hardware_id)
        if not valid:
            if "expired" in message.lower():
                messagebox.showerror("License Expired", f"Your license has expired: {message}\n\nPlease renew your license to continue using the automation features.")
            else:
                messagebox.showerror("License Error", f"License validation failed: {message}")
            return
        
        if not self.accounts:
            messagebox.showwarning("No Accounts", "Please load accounts first.")
            return
        
        self.automation_running = True
        self.stop_event.clear()
        self.start_btn.config(state='disabled')
        self.stop_btn.config(state='normal')
        self.progress_var.set(0)
        self.progress_label.config(text="Starting automation...")
        
        self.log_message("🚀 Starting automation process...")
        
        # Start automation in separate thread
        threading.Thread(target=self.run_automation, daemon=True).start()
    
    def run_automation(self):
        # CRITICAL: Check expiry before running automation
        _check_license_expiry_immediate()
        
        import concurrent.futures
        try:
            self.worker_threads = []
            completed_count = 0
            max_concurrent = self.max_concurrent_var.get()
            
            self.status_queue.put(("status", f"🚀 Starting automation with max {max_concurrent} concurrent browsers"))
            self.status_queue.put(("automation_started", len(self.accounts)))

            def thread_wrapper(email, password):
                try:
                    # Update tree status to Starting
                    self.status_queue.put(("update_status", (email, 'Starting...')))
                    self.status_queue.put(("status", f"[{email}] Browser launching..."))
                    
                    # Run the actual automation
                    google_automation_worker(email, password, self.status_queue, self.stop_event)
                    
                except Exception as e:
                    self.status_queue.put(("error", f"[{email}] Thread wrapper failed: {str(e)}"))

            # OPTIMIZED: Dynamic worker pool with immediate task assignment
            with concurrent.futures.ThreadPoolExecutor(max_workers=max_concurrent) as executor:
                # Track all accounts and active futures
                account_queue = list(enumerate(self.accounts))
                active_futures = {}  # future -> (email, account_index)
                completed_count = 0
                total_accounts = len(self.accounts)
                
                self.status_queue.put(("status", f"🚀 OPTIMIZED: Dynamic worker pool with {max_concurrent} browsers - Immediate task assignment!"))
                self.status_queue.put(("status", f"⚡ Workers will immediately process next account when current one completes - No waiting!"))
                
                # Initial batch - fill all available workers immediately
                initial_batch = min(max_concurrent, len(account_queue))
                for _ in range(initial_batch):
                    if account_queue and not self.stop_event.is_set():
                        i, account = account_queue.pop(0)
                        
                        # 🚨 IMMEDIATE LICENSE CHECK
                        _validate_license_for_operation(f"account_processing_{i+1}")
                        
                        email = account['email']
                        password = account['password']
                        
                        self.status_queue.put(("status", f"⚡ IMMEDIATE START: {email} (Worker {len(active_futures)+1}/{max_concurrent})"))
                        future = executor.submit(thread_wrapper, email, password)
                        active_futures[future] = (email, i)
                
                self.status_queue.put(("status", f"✅ {len(active_futures)} browsers launched immediately. {len(account_queue)} accounts queued for immediate assignment..."))
                
                # MAIN PROCESSING LOOP: Immediate worker assignment as tasks complete
                while active_futures and not self.stop_event.is_set():
                    # Wait for ANY worker to complete (immediate processing!)
                    done_futures = concurrent.futures.as_completed(active_futures.keys(), timeout=1.0)
                    
                    try:
                        for completed_future in done_futures:
                            email, account_index = active_futures[completed_future]
                            
                            try:
                                completed_future.result()  # Check for exceptions
                                completed_count += 1
                                progress = (completed_count / total_accounts) * 100
                                self.status_queue.put(("progress", progress))
                                self.status_queue.put(("status", f"⚡ {email} COMPLETED! ({completed_count}/{total_accounts}) - Worker freed!"))
                                
                            except Exception as e:
                                completed_count += 1
                                progress = (completed_count / total_accounts) * 100
                                self.status_queue.put(("progress", progress))
                                self.status_queue.put(("error", f"[{email}] Failed: {str(e)}"))
                                self.status_queue.put(("status", f"⚡ {email} FAILED - Worker freed for next task!"))
                            
                            # Remove completed future from active list
                            del active_futures[completed_future]
                            
                            # IMMEDIATE ASSIGNMENT: If more accounts waiting, assign immediately!
                            if account_queue and not self.stop_event.is_set():
                                next_i, next_account = account_queue.pop(0)
                                
                                try:
                                    _validate_license_for_operation(f"account_processing_{next_i+1}")
                                    next_email = next_account['email']
                                    next_password = next_account['password']
                                    
                                    self.status_queue.put(("status", f"🚀 IMMEDIATE ASSIGNMENT: {next_email} → Worker freed from {email}"))
                                    new_future = executor.submit(thread_wrapper, next_email, next_password)
                                    active_futures[new_future] = (next_email, next_i)
                                    
                                except Exception as assignment_error:
                                    self.status_queue.put(("error", f"Failed to assign {next_email}: {assignment_error}"))
                            else:
                                remaining_workers = len(active_futures)
                                remaining_tasks = len(account_queue)
                                self.status_queue.put(("status", f"📊 Worker freed - {remaining_workers} active, {remaining_tasks} queued"))
                            
                            # Break to check for more completions immediately
                            break
                            
                    except concurrent.futures.TimeoutError:
                        # No completions in the last second, continue monitoring
                        continue
                    except Exception as loop_error:
                        self.status_queue.put(("error", f"Processing loop error: {loop_error}"))
                        break

            if not self.stop_event.is_set():
                self.status_queue.put(("status", f"🎉 Dynamic worker optimization complete! All {completed_count} accounts processed with immediate task assignment."))
                self.status_queue.put(("status", f"⚡ Maximum efficiency achieved - No worker idle time!"))
                self.status_queue.put(("automation_complete", None))
                
        except Exception as e:
            self.status_queue.put(("error", f"❌ Automation controller failed: {str(e)}"))
        finally:
            self.status_queue.put(("finished", None))
    
    def stop_automation(self):
        self.automation_running = False
        self.stop_event.set()
        self.log_message("⏹️ Stopping automation...")
        
        self.start_btn.config(state='normal')
        self.stop_btn.config(state='disabled')
        self.progress_label.config(text="Stopped")
    
    def clear_accounts(self):
        self.accounts = []
        for item in self.accounts_tree.get_children():
            self.accounts_tree.delete(item)
        self.file_path_var.set("")
        self.progress_var.set(0)
        self.progress_label.config(text="Ready to start")
        self.start_btn.config(state='disabled')
        self.log_message("🗑️ Cleared all accounts")
    
    def log_message(self, message):
        timestamp = datetime.now().strftime("%H:%M:%S")
        formatted_message = f"[{timestamp}] {message}\n"
        self.log_text.insert(tk.END, formatted_message)
        self.log_text.see(tk.END)
        self.root.update_idletasks()
    
    def check_queue(self):
        try:
            while True:
                msg_type, data = self.status_queue.get_nowait()
                
                if msg_type == "status":
                    self.log_message(data)
                    
                elif msg_type == "success":
                    self.log_message(f"✅ {data}")
                    # Update tree status
                    email = data.split(']')[0].replace('[', '')
                    for item in self.accounts_tree.get_children():
                        if self.accounts_tree.item(item)['values'][0] == email:
                            self.accounts_tree.item(item, values=(email, 'Success'))
                            break
                            
                elif msg_type == "error":
                    self.log_message(f"❌ {data}")
                    # Update tree status
                    if '[' in data and ']' in data:
                        email = data.split(']')[0].replace('[', '')
                        for item in self.accounts_tree.get_children():
                            if self.accounts_tree.item(item)['values'][0] == email:
                                self.accounts_tree.item(item, values=(email, 'Failed'))
                                break
                
                elif msg_type == "completed":
                    email = data
                    for item in self.accounts_tree.get_children():
                        if self.accounts_tree.item(item)['values'][0] == email:
                            current_status = self.accounts_tree.item(item)['values'][1]
                            if current_status != 'Success':
                                self.accounts_tree.item(item, values=(email, 'Completed'))
                            break
                
                elif msg_type == "update_status":
                    email, status = data
                    for item in self.accounts_tree.get_children():
                        if self.accounts_tree.item(item)['values'][0] == email:
                            self.accounts_tree.item(item, values=(email, status))
                            break
                
                elif msg_type == "progress":
                    progress_value = data
                    self.progress_var.set(progress_value)
                    self.progress_label.config(text=f"Progress: {progress_value:.1f}%")
                
                elif msg_type == "automation_started":
                    self.log_message(f"🔥 Started automation for {data} accounts. Browsers launching...")
                
                elif msg_type == "automation_complete":
                    self.log_message("✅ All automation processes completed!")
                    self.progress_var.set(100)
                    self.progress_label.config(text="Completed")
                    self.start_btn.config(state='normal')
                    self.stop_btn.config(state='disabled')
                    self.automation_running = False
                
                elif msg_type == "finished":
                    self.start_btn.config(state='normal')
                    self.stop_btn.config(state='disabled')
                    self.automation_running = False
                    
        except queue.Empty:
            pass
        
        # Schedule next check with proper function reference
        if hasattr(self, 'root') and self.root.winfo_exists():
            try:
                self.root.after(100, self.check_queue)
            except tk.TclError:
                # Window is being destroyed, don't schedule more checks
                pass
    
    def copy_to_clipboard(self, text):
        """Copy text to clipboard"""
        try:
            self.root.clipboard_clear()
            self.root.clipboard_append(text)
            messagebox.showinfo("Copied", f"Copied to clipboard: {text[:30]}{'...' if len(text) > 30 else ''}")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to copy to clipboard: {e}")
    
    def check_license_validity(self):
        """Check and display current license validity"""
        # CRITICAL: Check expiry immediately
        _check_license_expiry_immediate()
        
        try:
            hardware_id = get_hardware_id()
            valid, message = validate_license_key("", hardware_id)
            
            if valid:
                license_info = self.get_license_details()
                if license_info:
                    try:
                        expiry_date = datetime.strptime(license_info['expiry'], '%Y-%m-%d')
                        days_left = (expiry_date - datetime.now()).days
                        
                        if days_left > 0:
                            status_msg = f"✅ License Valid\n\nExpires: {license_info['expiry']}\nDays remaining: {days_left}"
                            messagebox.showinfo("License Status", status_msg)
                        else:
                            status_msg = f"⚠️ License Expired\n\nExpired on: {license_info['expiry']}\nDays overdue: {abs(days_left)}"
                            messagebox.showwarning("License Status", status_msg)
                    except:
                        messagebox.showinfo("License Status", "✅ License Valid\n\nUnable to read expiry details")
                else:
                    messagebox.showinfo("License Status", "✅ License Valid\n\nNo detailed information available")
            else:
                messagebox.showerror("License Status", f"❌ License Invalid\n\n{message}")
                
            # Update status display
            self.show_license_status()
            
        except Exception as e:
            messagebox.showerror("Error", f"Failed to check license validity: {e}")
    
    def reactivate_license(self):
        """Show license reactivation dialog"""
        # CRITICAL: Check expiry before allowing reactivation
        _check_license_expiry_immediate()
        
        try:
            # Remove existing license file
            if os.path.exists("license.dat"):
                os.remove("license.dat")
            
            # Show activation window
            activation_result = show_license_window(self.root)
            
            if activation_result:
                messagebox.showinfo("Success", "License reactivated successfully!")
                self.show_license_status()
            else:
                messagebox.showwarning("Cancelled", "License reactivation was cancelled")
                
        except Exception as e:
            messagebox.showerror("Error", f"Failed to reactivate license: {e}")
    
    def show_user_guide(self):
        """Show comprehensive user guide"""
        guide_window = tk.Toplevel(self.root)
        guide_window.title("User Guide")
        guide_window.geometry("800x600")
        guide_window.resizable(True, True)
        
        # Center the window
        guide_window.update_idletasks()
        x = (guide_window.winfo_screenwidth() - 800) // 2
        y = (guide_window.winfo_screenheight() - 600) // 2
        guide_window.geometry(f"800x600+{x}+{y}")
        
        main_frame = ttk.Frame(guide_window, padding="20")
        main_frame.pack(fill='both', expand=True)
        
        # Title
        title_label = ttk.Label(main_frame, text="📖 User Guide", 
                               font=('Arial', 16, 'bold'))
        title_label.pack(pady=(0, 20))
        
        # Create notebook for tabs
        notebook = ttk.Notebook(main_frame)
        notebook.pack(fill='both', expand=True)
        
        # Getting Started tab
        start_frame = ttk.Frame(notebook, padding="10")
        notebook.add(start_frame, text="Getting Started")
        
        start_text = tk.Text(start_frame, wrap=tk.WORD, font=('Arial', 10))
        start_scroll = ttk.Scrollbar(start_frame, orient='vertical', command=start_text.yview)
        start_text.configure(yscrollcommand=start_scroll.set)
        start_text.pack(side='left', fill='both', expand=True)
        start_scroll.pack(side='right', fill='y')
        
        start_content = """Google Account Automation Tool - Getting Started
=======================================================

Welcome to the Google Account Automation Tool! This guide will help you get started with automating Google account setup, 2FA configuration, and app password generation.

🚀 QUICK START:
1. Ensure you have a valid license key
2. Prepare your accounts.csv file with email,password format
3. Load the CSV file using File > Load CSV or the Load CSV button
4. Configure your settings (concurrent browsers, etc.)
5. Click "Start Automation" to begin

📋 CSV FILE FORMAT:
Your CSV file should contain two columns (no headers needed):
- Column 1: Email address (e.g., user@gmail.com)
- Column 2: Password (e.g., mypassword123)

Example CSV content:
john.doe@gmail.com,password123
jane.smith@gmail.com,mypass456
test.account@gmail.com,secure789

💡 IMPORTANT NOTES:
• Each account should be a real Google account
• Passwords must be correct for successful automation
• 2FA should NOT be already enabled on accounts
• Chrome browser will be automatically managed
• Internet connection is required throughout the process

⚙️ SYSTEM REQUIREMENTS:
• Windows 10/11 (64-bit)
• 4GB RAM minimum (8GB recommended)
• Chrome browser (auto-downloaded if needed)
• Stable internet connection
• Valid license key for activation

🔧 SETTINGS CONFIGURATION:
• Concurrent Browsers: 1-20 (start with 3-5 for testing)
• Higher concurrency = faster processing but more resource usage
• Monitor system performance and adjust accordingly

📊 PROGRESS MONITORING:
• Real-time status updates in the log panel
• Progress bar shows overall completion
• Account tree shows individual status
• Green = Success, Red = Failed, Yellow = Processing

🎯 EXPECTED RESULTS:
For each successful account, the tool will:
✅ Enable 2FA (Two-Factor Authentication)
✅ Generate app password with proper formatting
✅ Collect 10 backup codes
✅ Save all data immediately to CSV files

📁 OUTPUT FILES:
• successful_accounts.csv - Contains working accounts with app passwords
• failed_accounts.csv - Contains accounts that encountered errors
• Files are created/updated immediately after each account"""
        
        start_text.insert('1.0', start_content)
        start_text.config(state='disabled')
        
        # Troubleshooting tab
        trouble_frame = ttk.Frame(notebook, padding="10")
        notebook.add(trouble_frame, text="Troubleshooting")
        
        trouble_text = tk.Text(trouble_frame, wrap=tk.WORD, font=('Arial', 10))
        trouble_scroll = ttk.Scrollbar(trouble_frame, orient='vertical', command=trouble_text.yview)
        trouble_text.configure(yscrollcommand=trouble_scroll.set)
        trouble_text.pack(side='left', fill='both', expand=True)
        trouble_scroll.pack(side='right', fill='y')
        
        trouble_content = """Troubleshooting Guide
=====================

🔍 COMMON ISSUES AND SOLUTIONS:

❌ "License validation failed"
Solution:
• Check internet connection
• Verify license key is correct
• Contact support if license should be valid
• Try License > Reactivate License

❌ "Could not extract app password"
Solution:
• Account may already have 2FA enabled
• Password might be incorrect
• Google may have security restrictions
• Try with a different account first

❌ "Chrome driver issues"
Solution:
• Tool auto-manages Chrome, no manual action needed
• If persistent, restart the application
• Ensure antivirus isn't blocking Chrome downloads

❌ "Automation stuck or slow"
Solution:
• Reduce concurrent browser count
• Check internet speed and stability
• Close other heavy applications
• Restart the tool if needed

❌ "CSV file loading errors"
Solution:
• Ensure CSV format is correct (email,password)
• Check for special characters in passwords
• Save CSV as UTF-8 encoding
• Remove any empty lines

⚠️ HIGH MEMORY USAGE:
• Reduce concurrent browsers to 3-5
• Close unnecessary applications
• Each browser uses ~200-500MB RAM
• Monitor system performance

🌐 NETWORK ISSUES:
• Stable internet required throughout process
• VPN may cause issues with Google detection
• Firewall should allow Chrome connections
• Consider using wired connection for stability

🔒 SECURITY CONSIDERATIONS:
• Tool is legitimate automation software
• Some antivirus may flag due to browser automation
• Add tool to antivirus exceptions if needed
• All automation uses official Google interfaces

📞 WHEN TO CONTACT SUPPORT:
• License activation failures
• Persistent technical errors
• Questions about commercial licensing
• Feature requests or bug reports

💡 OPTIMIZATION TIPS:
• Start with 1-2 concurrent browsers for testing
• Use high-quality Google accounts
• Ensure passwords are 100% correct
• Run during stable internet hours
• Monitor logs for specific error patterns"""
        
        trouble_text.insert('1.0', trouble_content)
        trouble_text.config(state='disabled')
        
        # Features tab
        features_frame = ttk.Frame(notebook, padding="10")
        notebook.add(features_frame, text="Features")
        
        features_text = tk.Text(features_frame, wrap=tk.WORD, font=('Arial', 10))
        features_scroll = ttk.Scrollbar(features_frame, orient='vertical', command=features_text.yview)
        features_text.configure(yscrollcommand=features_scroll.set)
        features_text.pack(side='left', fill='both', expand=True)
        features_scroll.pack(side='right', fill='y')
        
        features_content = """Feature Overview
================

🔐 GOOGLE ACCOUNT AUTOMATION:
• Automated Google account login
• 2FA (Two-Factor Authentication) setup
• App password generation with exact formatting
• Backup code collection (10 codes per account)
• Phone number verification handling
• Security challenge navigation

🌍 MULTI-LANGUAGE SUPPORT:
• 20+ language detection and handling
• Automatic English forcing for consistency
• Smart element detection across languages
• Fallback mechanisms for unknown languages
• Regional Google domain support

⚡ CONCURRENT PROCESSING:
• 1-20 simultaneous browser sessions
• Configurable concurrency levels
• Resource-aware processing
• Smart queuing and load balancing
• Real-time performance monitoring

💾 IMMEDIATE DATA EXPORT:
• Real-time CSV file creation
• App passwords saved with exact spacing
• Instant backup code storage
• No data loss even if interrupted
• Professional CSV formatting

🎨 PROFESSIONAL UI/UX:
• Modern, intuitive interface
• Real-time progress tracking
• Detailed logging and status updates
• Responsive design elements
• Professional color scheme and icons

🔒 SECURITY & LICENSING:
• Hardware-bound license system
• Encrypted license storage
• Anti-tampering mechanisms
• Server-based license validation
• Commercial-grade protection

📊 MONITORING & REPORTING:
• Real-time account status tracking
• Detailed success/failure logs
• Progress percentage display
• Individual account status indicators
• Comprehensive error reporting

🛠️ TECHNICAL FEATURES:
• Chrome browser optimization (20+ flags)
• Smart element finding algorithms
• Robust error handling and recovery
• Memory and resource management
• Network resilience and retry logic

🔧 ADVANCED SETTINGS:
• Configurable wait times
• Custom user agent strings
• Proxy support (if configured)
• Debug mode for troubleshooting
• Performance tuning options

📈 SCALABILITY:
• Handles small batches to hundreds of accounts
• Efficient resource utilization
• Parallel processing architecture
• Optimized for long-running operations
• Built for commercial deployment

✨ QUALITY ASSURANCE:
• Extensive testing across different scenarios
• Error recovery and retry mechanisms
• Data integrity verification
• Performance optimization
• Regular updates and improvements"""
        
        features_text.insert('1.0', features_content)
        features_text.config(state='disabled')
        
        # Close button
        ttk.Button(main_frame, text="Close", command=guide_window.destroy).pack(pady=(20, 0))
    
    def show_dev_info(self):
        """Show development and technical information"""
        dev_window = tk.Toplevel(self.root)
        dev_window.title("Development Information")
        dev_window.geometry("700x550")
        dev_window.resizable(False, False)
        
        # Center the window
        dev_window.update_idletasks()
        x = (dev_window.winfo_screenwidth() - 700) // 2
        y = (dev_window.winfo_screenheight() - 550) // 2
        dev_window.geometry(f"700x550+{x}+{y}")
        
        main_frame = ttk.Frame(dev_window, padding="20")
        main_frame.pack(fill='both', expand=True)
        
        # Title
        title_label = ttk.Label(main_frame, text="⚙️ Development Information", 
                               font=('Arial', 16, 'bold'))
        title_label.pack(pady=(0, 20))
        
        # Create text widget with scrollbar
        text_frame = ttk.Frame(main_frame)
        text_frame.pack(fill='both', expand=True)
        
        text_widget = tk.Text(text_frame, wrap=tk.WORD, font=('Courier', 9))
        scrollbar = ttk.Scrollbar(text_frame, orient='vertical', command=text_widget.yview)
        text_widget.configure(yscrollcommand=scrollbar.set)
        
        text_widget.pack(side='left', fill='both', expand=True)
        scrollbar.pack(side='right', fill='y')
        
        dev_content = f"""Google Account Automation Tool - Development Information
==========================================================

📋 PROJECT DETAILS:
Project Name: Google Account Automation Tool v3.0
Developer: AlgoLizen Solutions
Development Period: September 2025
Architecture: Python Desktop Application
Framework: Tkinter GUI + Selenium WebDriver

🏗️ TECHNICAL ARCHITECTURE:
• Language: Python 3.11+
• GUI Framework: Tkinter with ttk styling
• Automation Engine: Selenium WebDriver
• Browser: Chrome with custom optimization
• Encryption: AES-256 with HMAC validation
• License System: Hardware-bound with server validation
• Build System: PyInstaller for standalone executables

🔧 CORE COMPONENTS:
1. GoogleAutomationGUI - Main application interface
2. SmartElementFinder - Intelligent web element detection  
3. License System - Security and activation management
4. Concurrent Worker Pool - Multi-threaded automation
5. CSV Handler - Data import/export functionality
6. Progress Monitor - Real-time status tracking

⚙️ SELENIUM OPTIMIZATION:
Chrome Flags Applied: 20+ optimization flags
• --disable-blink-features=AutomationControlled
• --disable-dev-shm-usage --no-sandbox
• --disable-gpu --disable-extensions
• --disable-logging --silent --log-level=3
• Custom user agent and viewport settings
• Memory optimization and performance tuning

🌐 LANGUAGE FORCING SYSTEM:
Multi-layer approach for consistent English interface:
• Browser language preferences
• Accept-Language headers
• JavaScript locale overrides
• URL parameter forcing (hl=en)
• DOM manipulation for fallbacks
• 20+ language detection patterns

🔐 SECURITY IMPLEMENTATION:
License Protection:
• Hardware fingerprinting (MAC + CPU + Disk)
• AES-256 encryption with unique keys
• HMAC signature validation
• Server-based activation system
• Anti-debugging and tampering detection
• Runtime integrity checks

🗄️ DATA HANDLING:
• Thread-safe CSV operations with file locking
• Immediate data persistence (no buffering)
• UTF-8 encoding for international characters
• Error recovery and data integrity validation
• Real-time backup to prevent data loss

🧵 CONCURRENCY DESIGN:
• Thread pool for browser management
• Queue-based inter-thread communication
• Resource monitoring and throttling
• Graceful error handling and cleanup
• Memory leak prevention

📊 PERFORMANCE METRICS:
Typical Performance:
• Account processing: 2-5 minutes per account
• Memory usage: 200-500MB per browser
• CPU usage: Moderate during automation
• Network: ~10-50MB per account
• Success rate: 80-95% (depending on account quality)

🔍 ERROR HANDLING:
Multi-level error recovery:
• Network retry mechanisms (3 attempts)
• Element detection fallbacks (5+ strategies)
• Browser crash recovery
• Graceful degradation on failures
• Detailed error logging and reporting

📦 BUILD CONFIGURATION:
PyInstaller Settings:
• Single file executable (--onefile)
• Windows GUI application (--windowed)
• Hidden imports for all dependencies
• Icon and metadata embedding
• Size optimization and compression

🌟 VERSION HISTORY:
v3.0 (Current) - Production Release
• Complete license system integration
• Professional UI with menu system
• Advanced error handling
• Performance optimizations
• Comprehensive documentation

v2.x - Beta Versions
• Core automation functionality
• Basic license implementation
• Initial UI development

v1.x - Alpha Versions
• Proof of concept
• Basic automation scripts

🔮 FUTURE ENHANCEMENTS:
Planned Features:
• API integration options
• Custom reporting dashboard
• Advanced scheduling capabilities
• Plugin architecture
• Enterprise management tools

💻 DEVELOPMENT ENVIRONMENT:
• IDE: VS Code with Python extensions
• Version Control: Git
• Testing: Manual QA + automated scripts
• Debugging: Built-in Python debugger
• Documentation: Inline comments + user guides

🛠️ BUILD REQUIREMENTS:
Dependencies:
• selenium>=4.35.0
• pycryptodome>=3.23.0
• requests>=2.32.5
• tkinter (included with Python)
• Additional: PyInstaller, win32 libraries

System Requirements:
• Python 3.11+
• Windows 10/11 (64-bit)
• Chrome browser support
• Internet connectivity for licensing

📞 TECHNICAL SUPPORT:
For development-related inquiries:
• Code architecture questions
• Integration assistance  
• Custom feature development
• Enterprise licensing options
• API documentation requests

Current Build Information:
• Build Date: {datetime.now().strftime('%Y-%m-%d')}
• Hardware ID: {get_hardware_id()[:16]}...
• Python Version: {sys.version.split()[0]}
• Platform: {sys.platform}"""
        
        text_widget.insert('1.0', dev_content)
        text_widget.config(state='disabled')
        
        # Buttons
        button_frame = ttk.Frame(main_frame)
        button_frame.pack(pady=(20, 0))
        
        ttk.Button(button_frame, text="Copy Build Info", 
                  command=lambda: self.copy_to_clipboard(f"Build: {datetime.now().strftime('%Y-%m-%d')} | HW: {get_hardware_id()}")).pack(side='left', padx=(0, 10))
        ttk.Button(button_frame, text="Close", 
                  command=dev_window.destroy).pack(side='right')
    
    def show_about(self):
        """Show about dialog"""
        about_text = f"""Google Account Automation Tool v3.0

🏢 Developer: AlgoLizen Solutions
📅 Released: September 2025
🌐 Website: https://algolizen.com
📧 Support: Available through license portal

🎯 Purpose:
Professional automation tool for Google account setup, 
2FA configuration, and app password generation.

✨ Key Features:
• Multi-language support (20+ languages)
• Concurrent processing (1-20 browsers)
• Real-time progress tracking
• Professional UI/UX
• Secure licensing system
• Immediate data export

🔐 License:
Commercial software - Licensed for authorized use only
Hardware ID: {get_hardware_id()[:20]}...

© 2025 AlgoLizen Solutions. All rights reserved."""
        
        messagebox.showinfo("About", about_text)
    
    def show_license_status(self):
        """Show current license status in the status label"""
        try:
            # Check if the label exists first
            if not hasattr(self, 'license_status_label'):
                return
                
            hardware_id = get_hardware_id()
            valid, message = validate_license_key("", hardware_id)
            
            if valid:
                # Get license details
                license_info = self.get_license_details()
                if license_info and 'expiry' in license_info:
                    try:
                        days_left = (datetime.strptime(license_info['expiry'], '%Y-%m-%d') - datetime.now()).days
                        if days_left > 0:
                            self.license_status_label.config(
                                text=f"✅ Licensed to: {license_info['hardware_id'][:12]}... | Expires: {license_info['expiry']} ({days_left} days left)",
                                fg='#27ae60'
                            )
                        else:
                            self.license_status_label.config(
                                text=f"🚫 LICENSE EXPIRED on: {license_info['expiry']} ({abs(days_left)} days ago) - FUNCTIONALITY DISABLED",
                                fg='#e74c3c'
                            )
                            # Disable the start button for expired licenses
                            if hasattr(self, 'start_btn'):
                                self.start_btn.config(state='disabled')
                    except Exception:
                        self.license_status_label.config(
                            text=f"✅ Licensed to: {hardware_id[:12]}... | Status: Valid",
                            fg='#27ae60'
                        )
                else:
                    self.license_status_label.config(
                        text=f"✅ Licensed to: {hardware_id[:12]}... | Status: Valid",
                        fg='#27ae60'
                    )
            else:
                self.license_status_label.config(
                    text=f"❌ License invalid: {message}",
                    fg='#e74c3c'
                )
        except Exception as e:
            if hasattr(self, 'license_status_label'):
                self.license_status_label.config(
                    text=f"❌ License check failed: {str(e)[:50]}...",
                    fg='#e74c3c'
                )
    
    def get_license_details(self):
        """Get detailed license information"""
        try:
            if os.path.exists("license.dat"):
                with open("license.dat", 'r') as f:
                    encrypted_data = f.read().strip()
                decrypted = decrypt_license(encrypted_data)
                if decrypted:
                    return json.loads(decrypted)
        except:
            pass
        return None
    
    def start_periodic_license_check(self):
        """Start background thread for periodic license validation"""
        if not RUNTIME_VALIDATION_ACTIVE:
            safe_print("SECURITY VIOLATION: Runtime validation disabled!")
            os._exit(1)
        
        def periodic_check():
            while True:
                try:
                    time.sleep(30)  # Check every 30 seconds - AGGRESSIVE MONITORING
                    
                    # IMMEDIATE EXPIRY CHECK - TERMINATE IF EXPIRED
                    _check_license_expiry_immediate()
                    
                    # Comprehensive security validation
                    if not LICENSE_ENFORCEMENT_ACTIVE or not RUNTIME_VALIDATION_ACTIVE:
                        safe_print("SECURITY VIOLATION: Critical security flags disabled!")
                        os._exit(1)
                    
                    # Verify all obfuscated functions
                    if not _0x4c1c3ns3_ch3ck():
                        print("SECURITY VIOLATION: Primary license check failed!")
                        os._exit(1)
                    
                    if not _0x5d2e4f1a_v4l1d4t3():
                        print("SECURITY VIOLATION: Secondary validation failed!")
                        os._exit(1)
                        
                    if not _0x7f3a9b2c_s3cur1ty():
                        print("SECURITY VIOLATION: Security validation failed!")
                        os._exit(1)
                    
                    # Verify hardware binding is intact
                    hardware_id = get_hardware_id()
                    valid, _ = validate_license_key("", hardware_id)
                    if not valid:
                        print("SECURITY VIOLATION: License hardware binding compromised!")
                        os._exit(1)
                    
                    # Run integrity check
                    _verify_app_integrity()
                    
                except Exception as e:
                    print(f"SECURITY VIOLATION: Periodic validation error: {e}")
                    os._exit(1)
        
        # Start the background validation thread
        validation_thread = threading.Thread(target=periodic_check, daemon=True)
        validation_thread.start()

    def show_license_info(self):
        """Show detailed license information dialog"""
        # CRITICAL: Check expiry before showing license info
        _check_license_expiry_immediate()
        
        info_window = tk.Toplevel(self.root)
        info_window.title("License Information")
        info_window.geometry("600x500")
        info_window.resizable(False, False)
        
        # Center the window
        info_window.update_idletasks()
        x = (info_window.winfo_screenwidth() - 600) // 2
        y = (info_window.winfo_screenheight() - 500) // 2
        info_window.geometry(f"600x500+{x}+{y}")
        
        main_frame = ttk.Frame(info_window, padding="20")
        main_frame.pack(fill='both', expand=True)
        
        # Title
        title_label = ttk.Label(main_frame, text="📋 License Information", 
                               font=('Arial', 16, 'bold'))
        title_label.pack(pady=(0, 20))
        
        # Create text widget with scrollbar
        text_frame = ttk.Frame(main_frame)
        text_frame.pack(fill='both', expand=True)
        
        text_widget = tk.Text(text_frame, wrap=tk.WORD, font=('Courier', 10))
        scrollbar = ttk.Scrollbar(text_frame, orient='vertical', command=text_widget.yview)
        text_widget.configure(yscrollcommand=scrollbar.set)
        
        text_widget.pack(side='left', fill='both', expand=True)
        scrollbar.pack(side='right', fill='y')
        
        # Get license info
        hardware_id = get_hardware_id()
        license_info = self.get_license_details()
        valid, message = validate_license_key("", hardware_id)
        
        info_text = f"""Google Account Automation Tool - License Information
{"="*60}

Hardware Information:
• Hardware ID: {hardware_id}
• Computer Name: {os.environ.get('COMPUTERNAME', 'Unknown')}
• User: {os.environ.get('USERNAME', 'Unknown')}
• OS: {os.environ.get('OS', 'Unknown')}

License Status:
• Status: {'✅ Valid' if valid else '❌ Invalid'}
• Message: {message}
"""
        
        if license_info:
            try:
                expiry_date = datetime.strptime(license_info['expiry'], '%Y-%m-%d')
                days_left = (expiry_date - datetime.now()).days
                
                info_text += f"""
License Details:
• License Type: CALC (Commercial Application License)
• Issued To: {license_info['hardware_id']}
• Activation Date: {license_info.get('activation_date', 'Unknown')}
• Expiry Date: {license_info['expiry']}
• Days Remaining: {days_left} days
• Validated: {license_info.get('validated', False)}
• Version: {license_info.get('version', '3.0')}
"""
            except:
                info_text += """
License Details:
• Error reading license details
"""
        else:
            info_text += """
License Details:
• No license file found or license data corrupted
"""
        
        info_text += f"""

Application Information:
• Application: Google Account Automation Tool v3.0
• Developer: AlgoLizen Solutions
• Build Date: September 2025
• License Server: https://algolizen.com/activationserver/
• Support: Available through license portal

Features Included:
✅ Google Account Automation
✅ Multi-language Support (20+ languages)
✅ Concurrent Browser Sessions (1-20)
✅ 2FA Setup & App Password Generation
✅ Backup Code Collection
✅ Real-time Progress Tracking
✅ Immediate CSV Export
✅ Professional UI/UX
✅ Security & Anti-tampering

License Terms:
• This license is bound to the specific hardware ID shown above
• License cannot be transferred to other computers
• Tampering with license files will void the license
• Contact support for license issues or renewals
• Commercial use permitted under valid license

Technical Support:
• For technical issues, contact support with your Hardware ID
• License activation requires internet connection
• Ensure your system date/time is correct for proper validation

Version History:
• v3.0 - Production release with full feature set
• v2.x - Beta versions (deprecated)
• v1.x - Alpha versions (deprecated)
"""
        
        text_widget.insert('1.0', info_text)
        text_widget.config(state='disabled')
        
        # Buttons
        button_frame = ttk.Frame(main_frame)
        button_frame.pack(pady=(20, 0))
        
        ttk.Button(button_frame, text="Copy Hardware ID", 
                  command=lambda: self.copy_to_clipboard(hardware_id)).pack(side='left', padx=(0, 10))
        ttk.Button(button_frame, text="Refresh Status", 
                  command=lambda: [self.show_license_status(), info_window.destroy(), self.show_license_info()]).pack(side='left', padx=(0, 10))
        ttk.Button(button_frame, text="Close", 
                  command=info_window.destroy).pack(side='right')

def main():
    # ======================== IMMEDIATE LICENSE EXPIRY CHECK ========================
    # CHECK EXPIRY BEFORE ANYTHING ELSE - NO GUI, NO PROCESSING, NOTHING!
    safe_print("[CHECK] Checking license expiry status...")
    _check_license_expiry_immediate()
    safe_print("[OK] License expiry check passed - proceeding with application startup")
    
    # ======================== FINAL SECURITY VALIDATION ========================
    # Verify all security flags are properly set
    security_flags = [
        LICENSE_ENFORCEMENT_ACTIVE,
        ANTI_DEBUG_ACTIVE,
        INTEGRITY_CHECK_ACTIVE,
        RUNTIME_VALIDATION_ACTIVE
    ]
    
    if not all(security_flags):
        print("FATAL SECURITY VIOLATION: Critical security flags have been tampered with!")
        print(f"License Enforcement: {LICENSE_ENFORCEMENT_ACTIVE}")
        print(f"Anti-Debug: {ANTI_DEBUG_ACTIVE}")
        print(f"Integrity Check: {INTEGRITY_CHECK_ACTIVE}")
        print(f"Runtime Validation: {RUNTIME_VALIDATION_ACTIVE}")
        os._exit(1)
    
    # Verify critical functions exist and are callable
    critical_functions = [
        '_0x4c1c3ns3_ch3ck',
        '_0x5d2e4f1a_v4l1d4t3', 
        '_0x7f3a9b2c_s3cur1ty',
        '_validate_license_integrity',
        '_verify_app_integrity',
        'validate_license_key',
        'get_hardware_id'
    ]
    
    for func_name in critical_functions:
        if func_name not in globals() or not callable(globals()[func_name]):
            print(f"FATAL SECURITY VIOLATION: Critical function {func_name} is missing or corrupted!")
            os._exit(1)
    
    # ======================== SECURITY INITIALIZATION ========================
    # Anti-debugging check
    _anti_debug_check()
    
    # Anti-tampering check
    _verify_app_integrity()
    
    # Create hidden root window first
    root = tk.Tk()
    root.withdraw()  # Hide the main window initially
    
    # ======================== LICENSE CHECK ========================
    # Check license before starting the application
    hardware_id = get_hardware_id()
    print(f"Hardware ID: {hardware_id}")
    
    # Multiple validation layers
    valid1, message1 = validate_license_key("", hardware_id)
    valid2 = _0x4c1c3ns3_ch3ck()
    
    print(f"License validation 1: {valid1} ({message1})")
    print(f"License validation 2: {valid2}")
    
    if not (valid1 and valid2):
        # No valid license found or expired, show activation window
        if "expired" in message1.lower():
            print(f"License has expired: {message1}")
            print("Opening license activation window for renewal...")
        else:
            print("No valid license found. Opening license activation window...")
        print("Please wait while the license activation window loads...")
        
        try:
            activation_result = show_license_window(root)
            print(f"Activation window result: {activation_result}")
            
            if not activation_result:
                print("License activation cancelled or failed. Exiting...")
                try:
                    root.destroy()
                except:
                    pass
                sys.exit(1)
        except Exception as e:
            print(f"Error showing license window: {e}")
            import traceback
            traceback.print_exc()
            try:
                root.destroy()
            except:
                pass
            sys.exit(1)
        
        # Re-validate after activation
        print("Re-validating license after activation...")
        valid1, _ = validate_license_key("", hardware_id)
        valid2 = _0x4c1c3ns3_ch3ck()
        
        print(f"Re-validation 1: {valid1}")
        print(f"Re-validation 2: {valid2}")
        
        if not (valid1 and valid2):
            print("License activation verification failed. Exiting...")
            try:
                root.destroy()
            except:
                pass
            sys.exit(1)
    
    # Mark protection as active (after successful license validation)
    _protect_license_file.protection_active = True
    
    # Note: License file protection disabled to prevent runtime conflicts
    # _protect_license_file()  # Commented out to avoid file deletion detection issues
    
    # Start periodic license checking in background (reduced frequency)
    # periodic_license_check()  # Commented out to avoid conflicts with runtime checks
    
    # ======================== START APPLICATION ========================
    print("License validated. Starting Google Account Automation Tool...")
    
    # Create the application FIRST (this sets proper geometry)
    app = GoogleAutomationGUI(root)
    
    # Setup runtime license checking with proper function binding
    def setup_runtime_checks():
        """Setup runtime checks with proper function references"""
        def runtime_license_check():
            try:
                _verify_app_integrity()  # Continuous integrity checking
                if not _0x4c1c3ns3_ch3ck():
                    messagebox.showerror("License Error", "License validation failed during runtime.")
                    root.quit()
                    return
                # Schedule next check - reduced frequency to avoid conflicts
                root.after(300000, runtime_license_check)  # Check every 5 minutes instead of 1
            except Exception as e:
                print(f"Runtime check error: {e}")
                # Continue despite errors, but don't schedule another check
        
        # Start first check after 5 minutes
        root.after(300000, runtime_license_check)
    
    # Setup the runtime checks
    setup_runtime_checks()
    
    # NOW show the window (after geometry is set correctly)
    root.deiconify()  # Show the window with correct size and position
    root.mainloop()

if __name__ == "__main__":
    main()
