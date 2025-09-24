import tkinter as tk
from tkinter import ttk, filedialog, messagebox, scrolledtext
import csv
import time
import os
import threading
import queue
import tempfile
import shutil
import atexit
from datetime import datetime
from selenium import webdriver
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
        # Generate comprehensive multi-language selectors for backup codes button
        backup_code_texts = MULTI_LANG_TRANSLATIONS['get_backup_codes']
        backup_text_conditions = []
        for text in backup_code_texts:
            backup_text_conditions.extend([
                f'text()="{text}"',
                f'contains(text(), "{text}")',
                f'normalize-space(text())="{text}"',
                f'contains(normalize-space(text()), "{text}")',
                f'translate(text(), "ABCDEFGHIJKLMNOPQRSTUVWXYZ", "abcdefghijklmnopqrstuvwxyz")="{text.lower()}"'
            ])
        
        backup_combined_condition = ' or '.join(backup_text_conditions)
        
        get_codes_selectors = [
            f'//span[@jsname="V67aGc" and contains(@class, "AeBiU-vQzf8d") and ({backup_combined_condition})]',
            f'//button[.//span[{backup_combined_condition}]]',
            f'//span[contains(@class, "VfPpkd-vQzf8d") and ({backup_combined_condition})]',
            '//button[contains(translate(text(), "ABCDEFGHIJKLMNOPQRSTUVWXYZ", "abcdefghijklmnopqrstuvwxyz"), "backup") and contains(translate(text(), "ABCDEFGHIJKLMNOPQRSTUVWXYZ", "abcdefghijklmnopqrstuvwxyz"), "code")]',
            # Language-agnostic selectors as fallback
            '//button[contains(@class, "VfPpkd-LgbsSe")]',
            '//span[@jsname="V67aGc" and contains(@class, "AeBiU-vQzf8d")]',
            '//div[@role="button"]',
            '//button[@type="button"]'
        ]
        
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
    try:
        if stop_event.is_set():
            return
            
        status_queue.put(("status", f"Starting automation for {email}"))
        
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
            
            # Language and locale for consistency - support multiple languages
            options.add_argument("--lang=en-US")
            options.add_experimental_option("prefs", {
                "intl.accept_languages": "en-US,en,de,fr,es,it,pt,ru,ja,zh,ko,ar,hi",  # Multi-language support
                "profile.default_content_setting_values.notifications": 2,
                "profile.default_content_settings.popups": 0,
                "profile.managed_default_content_settings.images": 2,
                # Language-specific settings
                "translate.enabled": False,  # Disable automatic translation
                "translate_whitelists": {},
                "translate_denied_count_for_language": {},
                "translate.blocked_languages": []
            })
            
            # Set optimal permissions
            os.chmod(temp_dir, 0o755)

            service = Service()
            driver = webdriver.Chrome(service=service, options=options)
            
            # Enhanced anti-detection
            driver.execute_script("Object.defineProperty(navigator, 'webdriver', {get: () => undefined})")
            driver.execute_script("Object.defineProperty(navigator, 'languages', {get: () => ['en-US', 'en']})")
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
        
        # Multiple navigation attempts with different URLs
        login_urls = [
            "https://accounts.google.com/signin/v2/identifier",
            "https://accounts.google.com/signin",
            "https://accounts.google.com/"
        ]
        
        navigation_success = False
        for url in login_urls:
            try:
                driver.get(url)
                finder.wait_for_page_load()
                
                # Verify we're on the right page
                if "accounts.google.com" in driver.current_url:
                    navigation_success = True
                    status_queue.put(("status", f"[{email}] ✅ Successfully navigated to Google login"))
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
            
            # Generate comprehensive multi-language 2FA button selectors
            turn_on_texts = MULTI_LANG_TRANSLATIONS['turn_on']
            turn_on_text_conditions = []
            for text in turn_on_texts:
                turn_on_text_conditions.extend([
                    f'text()="{text}"',
                    f'contains(text(), "{text}")',
                    f'normalize-space(text())="{text}"',
                    f'contains(normalize-space(text()), "{text}")',
                    f'translate(text(), "ABCDEFGHIJKLMNOPQRSTUVWXYZ", "abcdefghijklmnopqrstuvwxyz")="{text.lower()}"'
                ])
            
            turn_on_combined_condition = ' or '.join(turn_on_text_conditions)
            
            # Comprehensive 2FA button selectors (language-independent)
            twofa_selectors = [
                # Original working selector
                '//*[@id="yDmH0d"]/c-wiz/div/div[2]/div[2]/c-wiz/div/div[1]/div[4]/div[2]/div/div/div/button/span[4]',
                # Generic button selectors with comprehensive language support
                f'//button[contains(@class, "VfPpkd-LgbsSe") and .//span[{turn_on_combined_condition}]]',
                f'//button[{turn_on_combined_condition}]',
                f'//span[@jsname="V67aGc" and ({turn_on_combined_condition})]',
                '//button[contains(@jsaction, "click") and contains(.//text(), "2-Step")]',
                '//div[contains(@class, "VfPpkd-RLmnJb")]//button[contains(@class, "VfPpkd-LgbsSe")]',
                '//button[@data-value="activate"]',
                '//button[contains(@class, "mdc-button--raised")]',
                # Fallback selectors
                '//c-wiz//button[contains(@class, "VfPpkd-LgbsSe")]',
                '//button[.//span[@class="VfPpkd-vQzf8d"]]',
                '//div[@role="button" and contains(@class, "VfPpkd-LgbsSe")]'
            ]
            
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
            
            # Generate comprehensive multi-language Next button selectors
            next_texts = MULTI_LANG_TRANSLATIONS['next']
            next_text_conditions = []
            for text in next_texts:
                next_text_conditions.extend([
                    f'text()="{text}"',
                    f'contains(text(), "{text}")',
                    f'normalize-space(text())="{text}"',
                    f'contains(normalize-space(text()), "{text}")',
                    f'translate(text(), "ABCDEFGHIJKLMNOPQRSTUVWXYZ", "abcdefghijklmnopqrstuvwxyz")="{text.lower()}"'
                ])
            
            next_combined_condition = ' or '.join(next_text_conditions)
            
            next_selectors = [
                # Language-specific text selectors with comprehensive coverage
                f'//button[.//span[@jsname="V67aGc" and ({next_combined_condition})]]',
                f'//div[@role="dialog"]//button[.//span[{next_combined_condition}]]',
                f'//button[{next_combined_condition}]',
                f'//span[@jsname="V67aGc" and ({next_combined_condition})]',
                # Modal-specific selectors
                '//div[contains(@class, "VfPpkd-T0kwCb")]//button[.//span[@jsname="V67aGc"]]',  # Modal container
                # Generic button selectors in modal context
                '//button[@data-mdc-dialog-action="next"]',
                '//button[contains(@class, "VfPpkd-LgbsSe") and .//span[@jsname="V67aGc"]]',
                '//div[@role="dialog"]//button[contains(@class, "mdc-button--raised")]',
                '//div[@role="dialog"]//button[contains(@class, "VfPpkd-LgbsSe--primary")]',
                # Position-based selectors (last resort)
                '//div[@role="dialog"]//button[last()]',
                '//div[@role="dialog"]//button[position()=last()]',
                # Very generic fallbacks
                '//button[.//span[@jsname="V67aGc"]]',
                '//button[contains(@class, "VfPpkd-LgbsSe")]'
            ]
            
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
                    
                    # Generate comprehensive multi-language Save button selectors
                    save_texts = MULTI_LANG_TRANSLATIONS['save']
                    save_text_conditions = []
                    for text in save_texts:
                        save_text_conditions.extend([
                            f'text()="{text}"',
                            f'contains(text(), "{text}")',
                            f'normalize-space(text())="{text}"',
                            f'contains(normalize-space(text()), "{text}")',
                            f'translate(text(), "ABCDEFGHIJKLMNOPQRSTUVWXYZ", "abcdefghijklmnopqrstuvwxyz")="{text.lower()}"'
                        ])
                    
                    save_combined_condition = ' or '.join(save_text_conditions)
                    
                    # Comprehensive Save button selectors for "Confirm your phone number" modal
                    save_selectors = [
                        # Specific Save button with data-mdc-dialog-action
                        '//button[@data-mdc-dialog-action="x8hlje" and @aria-label="Save phone number"]',
                        '//button[@data-mdc-dialog-action="x8hlje"]',
                        # Generic Save button text patterns (comprehensive multi-language)
                        f'//button[.//span[{save_combined_condition}]]',
                        f'//button[{save_combined_condition}]',
                        f'//span[@jsname="V67aGc" and ({save_combined_condition})]',
                        # Modal-specific Save button
                        f'//div[@role="dialog"]//button[.//span[{save_combined_condition}]]',
                        f'//div[@aria-modal="true"]//button[.//span[{save_combined_condition}]]',
                        # Save button by class and visibility
                        f'//button[contains(@class, "mUIrbf-LgbsSe") and not(@disabled) and not(contains(@style, "display: none")) and .//span[{save_combined_condition}]]',
                        # Data action patterns for Save
                        '//button[contains(@data-mdc-dialog-action, "save") or contains(@data-mdc-dialog-action, "x8hlje")]',
                        # Generic visible button in modal (last resort)
                        '//div[@role="dialog"]//button[not(@disabled) and not(contains(@style, "display: none"))][last()]',
                        '//div[@aria-modal="true"]//button[not(@disabled) and not(contains(@style, "display: none"))][last()]',
                        # JSName-based Save button
                        f'//button[.//span[@jsname="V67aGc" and ({save_combined_condition})]]'
                    ]
                    
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

            # Generate comprehensive multi-language Create button selectors
            create_texts = MULTI_LANG_TRANSLATIONS['create']
            create_text_conditions = []
            for text in create_texts:
                create_text_conditions.extend([
                    f'text()="{text}"',
                    f'contains(text(), "{text}")',
                    f'normalize-space(text())="{text}"',
                    f'contains(normalize-space(text()), "{text}")',
                    f'translate(text(), "ABCDEFGHIJKLMNOPQRSTUVWXYZ", "abcdefghijklmnopqrstuvwxyz")="{text.lower()}"'
                ])
            
            create_combined_condition = ' or '.join(create_text_conditions)
            
            # Click Create button using comprehensive language-independent selectors
            create_selectors = [
                f'//button[.//span[@jsname="V67aGc" and ({create_combined_condition})]]',
                f'//button[{create_combined_condition}]',
                f'//span[@jsname="V67aGc" and ({create_combined_condition})]',
                '//button[@data-action="create"]',
                '//button[contains(@class, "VfPpkd-LgbsSe") and contains(@class, "VfPpkd-LgbsSe--primary")]',
                '//button[.//span[@jsname="V67aGc"]]'  # Generic button with jsname span
            ]
            
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
        self.root = root
        self.root.title("Google Account Automation Tool")
        self.root.geometry("800x600")
        self.root.configure(bg='#f0f0f0')
        
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
    root = tk.Tk()
    app = GoogleAutomationGUI(root)
    root.mainloop()

if __name__ == "__main__":
    main()
