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
    print("License system requires pycryptodome. Install with: pip install pycryptodome")
    print(f"Import error: {e}")
    sys.exit(1)
import logging
from selenium.webdriver.common.by import By
from selenium.webdriver.common.keys import Keys
from selenium.webdriver.chrome.service import Service
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium.common.exceptions import TimeoutException, NoSuchElementException, ElementNotInteractableException
from selenium.webdriver.common.action_chains import ActionChains
import random
import json
from urllib.parse import urlparse

# ======================== LICENSE SYSTEM CONSTANTS ========================
# ⚠️ IMPORTANT: Configure these settings before deployment
LICENSE_SERVER_URL = "https://algolizen.com/activationserver"  # Your actual server URL
ACTIVATION_ENDPOINT = f"{LICENSE_SERVER_URL}/activate"  # Correct activation endpoint
VALIDATION_ENDPOINT = f"{LICENSE_SERVER_URL}/activate"  # Use same endpoint for validation

# ⚠️ SECURITY CRITICAL: Replace with your actual 32-byte secret key (base64 encoded recommended)
SECRET_KEY = b"REPLACE-WITH-YOUR-32-BYTE-SECRET"  # Must be exactly 32 bytes
HMAC_KEY = b"REPLACE-WITH-YOUR-HMAC-SECRET-KEY"  # Your HMAC secret for signatures

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
        cipher = AES.new(SECRET_KEY, AES.MODE_CBC)
        padded_data = pad(license_data.encode(), AES.block_size)
        encrypted = cipher.encrypt(padded_data)
        return b64encode(cipher.iv + encrypted).decode()
    except Exception as e:
        print(f"Encryption error: {e}")
        return None

def decrypt_license(encrypted_license):
    """Decrypt license data"""
    try:
        encrypted_data = b64decode(encrypted_license.encode())
        iv = encrypted_data[:16]
        ciphertext = encrypted_data[16:]
        cipher = AES.new(SECRET_KEY, AES.MODE_CBC, iv)
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
                # Save license locally
                license_data = {
                    'license_key': license_key,
                    'hardware_id': hardware_id,
                    'activated': True,
                    'timestamp': int(time.time())
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
    
    license_entry.bind('<Return>', on_enter)
    
    # Buttons
    button_frame = ttk.Frame(main_frame)
    button_frame.pack(side='bottom', fill='x', pady=(20, 0))
    
    ttk.Button(button_frame, text="Activate", command=activate).pack(side='right')
    ttk.Button(button_frame, text="Exit", command=sys.exit).pack(side='right', padx=(0, 10))
    
    # Instructions
    instructions = ttk.Label(main_frame, 
                           text="Instructions:\n1. Copy your Hardware ID\n2. Contact support to get your license key\n3. Enter the license key and click Activate",
                           justify='left', foreground='gray')
    instructions.pack(side='bottom', anchor='w', pady=(10, 0))
    
    license_window.protocol("WM_DELETE_WINDOW", sys.exit)
    license_window.wait_window()
    
    return activation_result['success']

def periodic_license_check():
    """Periodically check license validity (runs in background)"""
    def check_license():
        while True:
            try:
                hardware_id = get_hardware_id()
                valid, _ = validate_license_key("", hardware_id)
                if not valid:
                    # License became invalid, exit application
                    os._exit(1)
                time.sleep(1800)  # Check every 30 minutes
            except:
                time.sleep(1800)
    
    thread = threading.Thread(target=check_license, daemon=True)
    thread.start()

# Obfuscated license validation (makes reverse engineering harder)
def _0x4c1c3ns3_ch3ck():
    """Obfuscated license check - DO NOT REMOVE"""
    try:
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
        return license_info.get('hardware_id') == hw_id and license_info.get('activated', False)
    except:
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
                        print("License file appears corrupted. Application will exit.")
                        time.sleep(5)  # Give user time to see message
                        os._exit(1)
                else:
                    # Only exit if we've been running for a while (not during initial activation)
                    if hasattr(_protect_license_file, 'protection_active'):
                        print("License file was deleted during runtime. Application will exit.")
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

# Obfuscated license validation (makes reverse engineering harder)
def _0x4c1c3ns3_ch3ck():
    """Obfuscated license check - DO NOT REMOVE"""
    try:
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
        return license_info.get('hardware_id') == hw_id and license_info.get('activated', False)
    except:
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

# Smart element detection class
class SmartElementFinder:
    def __init__(self, driver, wait_time=15):
        self.driver = driver
        self.wait = WebDriverWait(driver, wait_time)
        self.short_wait = WebDriverWait(driver, 5)
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
    
    def wait_for_url_change(self, current_url, timeout=10, expected_contains=None):
        """Wait for URL to change from current URL"""
        end_time = time.time() + timeout
        while time.time() < end_time:
            try:
                new_url = self.driver.current_url
                if new_url != current_url:
                    if expected_contains is None or expected_contains in new_url:
                        return new_url
                time.sleep(0.5)
            except Exception:
                time.sleep(0.5)
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
        driver.get("https://myaccount.google.com/two-step-verification/backup-codes")
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
                time.sleep(3)  # Wait for codes to load
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
                                status_queue.put(("success", f"[{email}] ✅ Found backup code: {code_text}"))
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
                        status_queue.put(("success", f"[{email}] ✅ Found backup code via regex: {code}"))
                        if len(codes) >= 2:
                            break
            except Exception as e:
                status_queue.put(("status", f"[{email}] Fallback text parsing failed: {e}"))
        
        if codes:
            status_queue.put(("success", f"[{email}] 🔑 Collected {len(codes)} backup codes: {', '.join(codes[:2])}"))
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
                writer.writerow(["Email", "Password", "App Password", "Backup Code 1", "Backup Code 2", "Generated At"])
            
            # Ensure we have 2 backup codes or empty strings
            code1 = backup_codes[0] if backup_codes and len(backup_codes) > 0 else ""
            code2 = backup_codes[1] if backup_codes and len(backup_codes) > 1 else ""
            
            # Write immediately to CSV with explicit flush
            writer.writerow([email, password, app_password, code1, code2, datetime.now().strftime("%Y-%m-%d %H:%M:%S")])
            f.flush()  # Force immediate write to disk
            os.fsync(f.fileno())  # Ensure data is written to disk immediately
            
        # Return confirmation of what was saved
        return {
            'email': email,
            'app_password': app_password,
            'backup_codes': [code1, code2] if code1 or code2 else [],
            'saved_at': datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        }

def save_failed_account(email, password, reason):
    """Save failed account with reason to CSV"""
    with file_lock:
        file_exists = os.path.isfile("failed_accounts.csv")
        with open("failed_accounts.csv", mode="a", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            if not file_exists:
                writer.writerow(["Email", "Password", "Failure Reason", "Failed At"])
            writer.writerow([email, password, reason, datetime.now().strftime("%Y-%m-%d %H:%M:%S")])

def google_automation_worker(email, password, status_queue, stop_event):
    """Worker function for Google automation running in a separate thread"""
    # CRITICAL: License validation before starting automation
    if not _0x4c1c3ns3_ch3ck():
        status_queue.put(("error", f"[{email}] ❌ License validation failed"))
        return
    
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
            
            # Performance optimizations
            options.add_argument("--no-sandbox")
            options.add_argument("--disable-dev-shm-usage")
            options.add_argument("--disable-gpu")
            options.add_argument("--disable-web-security")
            options.add_argument("--disable-features=VizDisplayCompositor")
            options.add_argument("--disable-extensions")
            options.add_argument("--disable-plugins")
            options.add_argument("--disable-images")
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
            
            # Memory and performance
            options.add_argument("--memory-pressure-off")
            options.add_argument("--max_old_space_size=4096")
            options.add_argument("--aggressive-cache-discard")
            
            # User data and debugging
            options.add_argument(f"--user-data-dir={temp_dir}")
            options.add_argument("--remote-debugging-port=0")
            
            # AGGRESSIVE LANGUAGE FORCING - ENGLISH ONLY - NO EXCEPTIONS
            options.add_argument("--lang=en-US")
            options.add_argument("--accept-lang=en-US,en;q=1.0")
            options.add_argument("--accept-language=en-US,en;q=1.0")
            options.add_argument("--disable-translate")
            options.add_argument("--disable-extensions-http-throttling")
            options.add_argument("--disable-locale-switching-bho")
            
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

            service = Service()
            driver = webdriver.Chrome(service=service, options=options)
            
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
            save_failed_account(email, password, f"Chrome setup failed: {chrome_error}")
            if temp_dir and os.path.exists(temp_dir):
                try:
                    shutil.rmtree(temp_dir, ignore_errors=True)
                except:
                    pass
            return

        # Step 1: Smart navigation to Google login
        if stop_event.is_set():
            status_queue.put(("status", f"[{email}] Stopped - Browser left open"))
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
        
        time.sleep(2)  # Allow page to stabilize

        # Step 2: Smart email entry with validation
        if stop_event.is_set():
            status_queue.put(("status", f"[{email}] Stopped - Browser left open"))
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
            time.sleep(2)
            status_queue.put(("status", f"[{email}] ✅ Email entered successfully"))
            
        except Exception as e:
            status_queue.put(("error", f"[{email}] Email entry failed: {e}"))
            save_failed_account(email, password, f"Email entry failed: {e}")
            status_queue.put(("status", f"[{email}] Browser left open for manual email entry"))
            return

        # Step 3: Smart password entry with multiple strategies
        if stop_event.is_set():
            status_queue.put(("status", f"[{email}] Stopped - Browser left open"))
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
            
            # Smart wait for login completion
            new_url = finder.wait_for_url_change(current_url, timeout=15, expected_contains="myaccount")
            if new_url:
                status_queue.put(("status", f"[{email}] ✅ Password accepted, redirecting..."))
            
            time.sleep(3)
            
        except Exception as e:
            status_queue.put(("error", f"[{email}] Password entry failed: {e}"))
            save_failed_account(email, password, f"Password entry failed: {e}")
            status_queue.put(("status", f"[{email}] Browser left open for manual password entry"))
            return

        # Step 4: Smart login verification
        try:
            status_queue.put(("status", f"[{email}] Verifying successful login"))
            
            # Multiple success indicators
            success_patterns = [
                "myaccount.google.com",
                "accounts.google.com/ManageAccount",
                "accounts.google.com/b/0/ManageAccount"
            ]
            
            login_verified = False
            for pattern in success_patterns:
                try:
                    finder.wait.until(EC.url_contains(pattern))
                    login_verified = True
                    break
                except TimeoutException:
                    continue
            
            if not login_verified:
                # Check for common login obstacles
                current_url = driver.current_url
                page_source = driver.page_source.lower()
                
                if "challenge" in current_url or "challenge" in page_source:
                    raise Exception("Account requires additional verification/challenge")
                elif "captcha" in page_source:
                    raise Exception("CAPTCHA verification required")
                elif "suspicious" in page_source:
                    raise Exception("Suspicious activity detected")
                else:
                    raise Exception("Login verification failed - unknown issue")
            
            status_queue.put(("status", f"[{email}] ✅ Login verified successfully"))
            
        except Exception as e:
            status_queue.put(("error", f"[{email}] Login verification failed: {e}"))
            save_failed_account(email, password, f"Login verification failed: {e}")
            status_queue.put(("status", f"[{email}] Browser left open for manual login verification"))
            return

        # Step 5: Smart 2FA navigation
        if stop_event.is_set():
            status_queue.put(("status", f"[{email}] Stopped - Browser left open"))
            return
            
        status_queue.put(("status", f"[{email}] Smart navigation to 2FA settings"))
        
        # Multiple 2FA URLs to try
        twofa_urls = [
            "https://myaccount.google.com/signinoptions/twosv",
            "https://myaccount.google.com/security/signinoptions/twosv",
            "https://accounts.google.com/b/0/signinoptions/twosv"
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
            time.sleep(3)
            page_source = driver.page_source.lower()
            if "phone" in page_source or "number" in page_source or "verify" in page_source:
                status_queue.put(("status", f"[{email}] ✅ 2FA setup initiated successfully"))
            else:
                status_queue.put(("status", f"[{email}] ⚠️ 2FA button clicked, verifying setup progress..."))
            
        except Exception as e:
            status_queue.put(("error", f"[{email}] 2FA button detection failed: {e}"))
            save_failed_account(email, password, f"2FA button not found: {e}")
            status_queue.put(("status", f"[{email}] Browser left open for manual 2FA setup"))
            return

        # Step 7: Smart phone number entry with intelligent generation
        try:
            if stop_event.is_set():
                status_queue.put(("status", f"[{email}] Stopped - Browser left open"))
                return
                
            status_queue.put(("status", f"[{email}] Smart phone number entry"))
            time.sleep(3)  # Allow modal to fully load
            
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
                    time.sleep(3)  # Allow modal transition and phone confirmation modal to appear
                    
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
                            time.sleep(3)  # Allow modal to close and next step to begin
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
            status_queue.put(("status", f"[{email}] Browser left open for manual debugging"))
            return

        # Skip "You're now protected" modal - Direct navigation to app passwords
        if stop_event.is_set():
            status_queue.put(("status", f"[{email}] Stopped - Browser left open"))
            return
            
        status_queue.put(("status", f"[{email}] Skipping 2FA completion modal - navigating directly to App Passwords"))
        time.sleep(2)  # Brief pause to ensure 2FA setup completes
        
        # Direct navigation to app passwords page (saves time)
        try:
            status_queue.put(("status", f"[{email}] Smart navigation to App Passwords page"))
            
            # Multiple app password URLs to try
            app_password_urls = [
                "https://myaccount.google.com/apppasswords",
                "https://myaccount.google.com/security/signinoptions/twosv/apppasswords",
                "https://accounts.google.com/b/0/apppasswords"
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
            status_queue.put(("status", f"[{email}] Browser left open for manual navigation"))
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
                spans = strong.find_elements(By.TAG_NAME, 'span')
                app_password = ''.join([span.text for span in spans]).replace(' ', '')
                status_queue.put(("success", f"[{email}] 🔑 Generated app password: {app_password}"))
                
                # Collect backup codes after getting app password
                backup_codes = collect_backup_codes(driver, finder, email, status_queue)
                
                # IMMEDIATE SAVE - Save app password and backup codes together RIGHT NOW
                status_queue.put(("status", f"[{email}] 💾 Saving app password and backup codes to CSV immediately..."))
                save_result = save_app_password(email, password, app_password, backup_codes)
                
                # Confirm immediate save success with details
                backup_count = len(backup_codes) if backup_codes else 0
                status_queue.put(("success", f"[{email}] ✅ SAVED IMMEDIATELY: App password + {backup_count} backup codes written to CSV"))
                status_queue.put(("success", f"[{email}] 📝 File: successful_accounts.csv | Time: {save_result['saved_at']}"))
                status_queue.put(("update_status", (email, 'Success - Saved')))
                
            except Exception as e:
                status_queue.put(("error", f"[{email}] Could not extract app password: {e}"))
                save_failed_account(email, password, f"Could not extract app password: {e}")
                status_queue.put(("update_status", (email, 'Failed')))

        except Exception as e:
            status_queue.put(("error", f"[{email}] App password creation failed: {e}"))
            save_failed_account(email, password, f"App password creation failed: {e}")

        # Mark automation as completed successfully
        status_queue.put(("status", f"[{email}] ✅ Automation completed successfully - Browser left open for review"))
        status_queue.put(("completed", email))

    except Exception as e:
        status_queue.put(("error", f"[{email}] Automation failed: {e}"))
        save_failed_account(email, password, f"Automation failed: {e}")
        # Keep browser open even on error for manual inspection
        if driver is not None:
            status_queue.put(("status", f"[{email}] Browser left open for manual review/correction"))
    finally:
        # Clean up temporary directory
        if temp_dir and os.path.exists(temp_dir):
            try:
                shutil.rmtree(temp_dir, ignore_errors=True)
            except:
                pass

class GoogleAutomationGUI:
    def __init__(self, root):
        # CRITICAL: License validation at GUI initialization
        if not _0x4c1c3ns3_ch3ck():
            messagebox.showerror("License Error", "Invalid or expired license. Please restart the application.")
            sys.exit(1)
        
        # Additional integrity check
        _verify_app_integrity()
        
        self.root = root
        self.root.title("Google Account Automation Tool")
        self.root.configure(bg='#f0f0f0')
        
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
        self.check_queue()
    
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
        # CRITICAL: License check before starting automation
        if not _0x4c1c3ns3_ch3ck():
            messagebox.showerror("License Error", "License validation failed. Please restart the application.")
            sys.exit(1)
        
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

            # Use ThreadPoolExecutor to limit concurrent browsers
            with concurrent.futures.ThreadPoolExecutor(max_workers=max_concurrent) as executor:
                futures = []
                
                # Submit all tasks
                for i, account in enumerate(self.accounts):
                    if self.stop_event.is_set():
                        break
                        
                    email = account['email']
                    password = account['password']
                    
                    self.status_queue.put(("status", f"📝 Queuing {email} (Position {i+1}/{len(self.accounts)})"))
                    future = executor.submit(thread_wrapper, email, password)
                    futures.append((future, email))
                    
                    # Small delay to stagger starts
                    time.sleep(0.5)
                
                self.status_queue.put(("status", f"✅ All {len(futures)} tasks queued. Processing with {max_concurrent} concurrent browsers..."))
                
                # Wait for completion and handle results
                completed = 0
                for future, email in futures:
                    try:
                        future.result()  # This will raise any exception that occurred
                        completed += 1
                        progress = (completed / len(futures)) * 100
                        self.status_queue.put(("progress", progress))
                        self.status_queue.put(("status", f"📊 Progress: {completed}/{len(futures)} accounts processed ({progress:.1f}%)"))
                        
                    except Exception as e:
                        self.status_queue.put(("error", f"[{email}] Automation failed: {str(e)}"))

            if not self.stop_event.is_set():
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
        
        # Schedule next check
        self.root.after(100, self.check_queue)

def main():
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
        # No valid license found, show activation window
        print("No valid license found. Opening license activation window...")
        print("Please wait while the license activation window loads...")
        
        try:
            activation_result = show_license_window(root)
            print(f"Activation window result: {activation_result}")
            
            if not activation_result:
                print("License activation cancelled or failed. Exiting...")
                root.destroy()
                sys.exit(1)
        except Exception as e:
            print(f"Error showing license window: {e}")
            import traceback
            traceback.print_exc()
            root.destroy()
            sys.exit(1)
        
        # Re-validate after activation
        print("Re-validating license after activation...")
        valid1, _ = validate_license_key("", hardware_id)
        valid2 = _0x4c1c3ns3_ch3ck()
        
        print(f"Re-validation 1: {valid1}")
        print(f"Re-validation 2: {valid2}")
        
        if not (valid1 and valid2):
            print("License activation verification failed. Exiting...")
            root.destroy()
            sys.exit(1)
    
    # Mark protection as active (after successful license validation)
    _protect_license_file.protection_active = True
    
    # Start license file protection (now that we have a valid license)
    _protect_license_file()
    
    # Start periodic license checking in background
    periodic_license_check()
    
    # ======================== START APPLICATION ========================
    print("License validated. Starting Google Account Automation Tool...")
    
    # Show the main window now
    root.deiconify()  # Show the hidden root window
    
    # Additional runtime check
    def runtime_license_check():
        _verify_app_integrity()  # Continuous integrity checking
        if not _0x4c1c3ns3_ch3ck():
            messagebox.showerror("License Error", "License validation failed during runtime.")
            os._exit(1)
        root.after(60000, runtime_license_check)  # Check every minute
    
    # Start runtime checking
    root.after(60000, runtime_license_check)
    
    app = GoogleAutomationGUI(root)
    root.mainloop()

if __name__ == "__main__":
    main()
