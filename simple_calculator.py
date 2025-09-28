

# Dependency check
try:
    import tkinter as tk
    from tkinter import messagebox
    import os
    import uuid
    import platform
    import hashlib
    import subprocess
    import datetime
    import hmac
    import requests
    from base64 import b64encode, b64decode
    from Crypto.Cipher import AES
    from Crypto.Util.Padding import pad, unpad
except ImportError as e:
    print("A required package is missing:", e)
    print("Please install all requirements with: pip install pycryptodome requests")
    exit(1)

import json
import logging
LOG_FILE = "license_log.txt"
logging.basicConfig(filename=LOG_FILE, level=logging.INFO, format='%(asctime)s %(levelname)s: %(message)s')

# Configuration - no external file needed
SECRET_KEY = "12345678".encode()
SERVER_URL = "https://algolizen.com/activationserver/activate"

LICENSE_FILE = "license.key"
LAST_CHECK_FILE = "last_check.dat"
OFFLINE_GRACE_DAYS = 7  # Allow 7 days of offline usage after last successful online check


# Advanced hardware ID: combine MAC, disk serial, and CPU info, then hash
import platform
import hashlib
import subprocess

def get_mac():
    return str(uuid.getnode())

def get_disk_serial():
    try:
        if os.name == 'nt':
            # Windows
            output = subprocess.check_output('wmic diskdrive get SerialNumber', shell=True).decode()
            lines = output.splitlines()
            for line in lines:
                line = line.strip()
                if line and 'SerialNumber' not in line:
                    return line
        else:
            # Linux/Mac
            output = subprocess.check_output(['lsblk', '-o', 'SERIAL']).decode()
            lines = output.splitlines()
            for line in lines:
                line = line.strip()
                if line and 'SERIAL' not in line:
                    return line
    except Exception:
        return 'unknown'
    return 'unknown'

def get_cpu_info():
    try:
        if os.name == 'nt':
            output = subprocess.check_output('wmic cpu get ProcessorId', shell=True).decode()
            lines = output.splitlines()
            for line in lines:
                line = line.strip()
                if line and 'ProcessorId' not in line:
                    return line
        else:
            output = subprocess.check_output(['cat', '/proc/cpuinfo']).decode()
            for line in output.splitlines():
                if 'Serial' in line or 'ID' in line:
                    return line.split(':')[-1].strip()
    except Exception:
        return 'unknown'
    return 'unknown'

def get_hardware_id():
    mac = get_mac()
    disk = get_disk_serial()
    cpu = get_cpu_info()
    raw = f"{mac}-{disk}-{cpu}"
    # Hash for obfuscation
    return hashlib.sha256(raw.encode()).hexdigest()



import datetime
import hmac
import hashlib
import requests
from base64 import b64encode, b64decode
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad





# AES encryption for license file
def get_aes_key():
    # Derive a 32-byte key from the hardware ID
    hwid = get_hardware_id()
    return hashlib.sha256(hwid.encode()).digest()

def encrypt_license(plain):
    key = get_aes_key()
    cipher = AES.new(key, AES.MODE_CBC)
    ct_bytes = cipher.encrypt(pad(plain.encode(), AES.block_size))
    iv = b64encode(cipher.iv).decode('utf-8')
    ct = b64encode(ct_bytes).decode('utf-8')
    return iv + ':' + ct

def decrypt_license(enc):
    key = get_aes_key()
    try:
        iv, ct = enc.split(':')
        iv = b64decode(iv)
        ct = b64decode(ct)
        cipher = AES.new(key, AES.MODE_CBC, iv)
        pt = unpad(cipher.decrypt(ct), AES.block_size)
        return pt.decode('utf-8')
    except Exception:
        return None

# Functions to manage last online check timestamp
def save_last_check_time():
    """Save the current timestamp as the last successful online check"""
    try:
        with open(LAST_CHECK_FILE, 'w') as f:
            f.write(str(datetime.datetime.now().timestamp()))
    except Exception:
        pass

def get_last_check_time():
    """Get the timestamp of the last successful online check"""
    try:
        with open(LAST_CHECK_FILE, 'r') as f:
            return datetime.datetime.fromtimestamp(float(f.read().strip()))
    except Exception:
        return None

def is_within_grace_period():
    """Check if we're still within the offline grace period"""
    last_check = get_last_check_time()
    if last_check is None:
        return False
    
    days_since_check = (datetime.datetime.now() - last_check).days
    return days_since_check <= OFFLINE_GRACE_DAYS

# License key format: CALC-<reversed_hardware_id>-<expiry_date:YYYYMMDD>-<signature>
def generate_license_signature(hardware_id, expiry_date):
    msg = f"{hardware_id[::-1]}-{expiry_date}".encode()
    return hmac.new(SECRET_KEY, msg, hashlib.sha256).hexdigest()[:16]

def generate_license_key(hardware_id, expiry_date):
    sig = generate_license_signature(hardware_id, expiry_date)
    return f"CALC-{hardware_id[::-1]}-{expiry_date}-{sig}"




def show_license_window(change=False):
    hardware_id = get_hardware_id()
    def submit_key():
        user_key = license_entry.get().strip()
        # Try online activation first
        try:
            resp = requests.post(
                SERVER_URL,
                json={"hardware_id": hardware_id, "license_key": user_key},
                timeout=5
            )
            data = resp.json()
            if data.get('status') == 'ok':
                with open(LICENSE_FILE, 'w') as f:
                    f.write(encrypt_license(user_key))
                save_last_check_time()  # Save successful activation time
                logging.info(f"License activated for HWID {hardware_id}")
                messagebox.showinfo("License", "License key accepted and activated online.")
                license_window.destroy()
                if change:
                    update_license_status()
                else:
                    root.deiconify()
                return
            else:
                logging.warning(f"Activation failed for HWID {hardware_id}: {data.get('message')}")
                messagebox.showerror("License Error", data.get('message', 'Activation failed.'))
                return
        except Exception as e:
            logging.error(f"Activation server error: {e}")
            messagebox.showerror("License Error", "Could not connect to activation server.")
            return

    def copy_hardware_id():
        license_window.clipboard_clear()
        license_window.clipboard_append(hardware_id)
        messagebox.showinfo("Copied", "Hardware ID copied to clipboard.")

    def show_help():
        msg = (
            "How to get a license key:\n\n"
            "1. Copy your Hardware ID using the button below.\n"
            "2. Send your Hardware ID to the software provider.\n"
            "3. The provider will send you a license key.\n"
            "4. Enter the license key below and click Submit."
        )
        messagebox.showinfo("How to get a License Key", msg)

    license_window = tk.Toplevel()
    license_window.title("Enter License Key" if not change else "Change License Key")
    license_window.grab_set()
    tk.Label(license_window, text="Hardware ID:").pack(padx=10, pady=5)
    tk.Entry(license_window, state='readonly', width=40, justify='center',
             fg='blue',
             textvariable=tk.StringVar(value=hardware_id)).pack(padx=10, pady=5)
    tk.Button(license_window, text="Copy Hardware ID", command=copy_hardware_id).pack(pady=2)
    tk.Button(license_window, text="How to get a License Key?", command=show_help).pack(pady=2)
    tk.Label(license_window, text="Enter License Key:").pack(padx=10, pady=5)
    license_entry = tk.Entry(license_window, width=40)
    license_entry.pack(padx=10, pady=5)
    tk.Button(license_window, text="Submit", command=submit_key).pack(pady=10)
    license_window.protocol("WM_DELETE_WINDOW", lambda: (root.destroy() if not change else license_window.destroy()))
    license_window.mainloop()

def validate_license_key(key, hardware_id):
    # Format: CALC-<reversed_hardware_id>-<expiry>-<sig>
    try:
        if not key.startswith("CALC-"):
            return False
        parts = key.split("-")
        if len(parts) != 4:
            return False
        reversed_id, expiry, sig = parts[1], parts[2], parts[3]
        if reversed_id != hardware_id[::-1]:
            return False
        expiry_date = datetime.datetime.strptime(expiry, "%Y%m%d")
        if expiry_date < datetime.datetime.now():
            return False
        expected_sig = generate_license_signature(hardware_id, expiry)
        if not hmac.compare_digest(sig, expected_sig):
            return False
        return True
    except Exception:
        return False

def get_license_expiry(key):
    try:
        parts = key.split("-")
        if len(parts) >= 3:
            expiry = parts[2]
            expiry_date = datetime.datetime.strptime(expiry, "%Y%m%d")
            return expiry_date
    except Exception:
        pass
    return None


# Require online activation every time the app starts, and re-check every 24 hours
import threading
import time

def is_license_valid_online():
    hardware_id = get_hardware_id()
    if os.path.exists(LICENSE_FILE):
        with open(LICENSE_FILE, 'r') as f:
            enc = f.read().strip()
        saved_key = decrypt_license(enc)
        if not saved_key:
            logging.warning(f"Corrupted or invalid license file for HWID {hardware_id}")
            return False
        
        # First check if the license is valid locally
        if not validate_license_key(saved_key, hardware_id):
            logging.warning(f"Local license validation failed for HWID {hardware_id}")
            return False
        
        # If we're within grace period, don't require online check
        if is_within_grace_period():
            logging.info(f"License check skipped - within grace period for HWID {hardware_id}")
            return True
        
        # Perform online check
        try:
            resp = requests.post(
                SERVER_URL,
                json={"hardware_id": hardware_id, "license_key": saved_key},
                timeout=5
            )
            data = resp.json()
            if data.get('status') == 'ok':
                save_last_check_time()  # Save successful check time
                logging.info(f"Online license check successful for HWID {hardware_id}")
                return True
            else:
                logging.warning(f"Online check failed for HWID {hardware_id}: {data.get('message')}")
                return False
        except Exception as e:
            logging.error(f"Online check server error: {e}")
            # If we can't reach server but license is valid locally and not expired, allow usage
            if validate_license_key(saved_key, hardware_id):
                logging.info(f"Allowing offline usage due to server error for HWID {hardware_id}")
                return True
            return False
    return False

def periodic_license_check():
    while True:
        time.sleep(24 * 60 * 60)  # 24 hours
        # Only check if we're outside the grace period
        if not is_within_grace_period():
            if not is_license_valid_online():
                messagebox.showerror("License Error", f"License re-check failed after {OFFLINE_GRACE_DAYS} days. Please reconnect to the internet for license verification.")
                root.destroy()
                break

def update_license_status():
    hardware_id = get_hardware_id()
    if os.path.exists(LICENSE_FILE):
        with open(LICENSE_FILE, 'r') as f:
            enc = f.read().strip()
        saved_key = decrypt_license(enc)
        if not saved_key:
            license_status.set("Invalid or corrupted license file")
            return
        if validate_license_key(saved_key, hardware_id):
            expiry = get_license_expiry(saved_key)
            last_check = get_last_check_time()
            
            if expiry:
                days_left = (expiry - datetime.datetime.now()).days
                if days_left < 0:
                    license_status.set(f"Expired on {expiry.date()}")
                elif days_left < 7:
                    license_status.set(f"Expiring soon: {expiry.date()} ({days_left} days left)")
                else:
                    base_status = f"Valid until {expiry.date()} ({days_left} days left)"
                    if last_check and is_within_grace_period():
                        days_since_check = (datetime.datetime.now() - last_check).days
                        remaining_offline = OFFLINE_GRACE_DAYS - days_since_check
                        license_status.set(f"{base_status} - Offline grace: {remaining_offline} days")
                    else:
                        license_status.set(base_status)
            else:
                if last_check and is_within_grace_period():
                    days_since_check = (datetime.datetime.now() - last_check).days
                    remaining_offline = OFFLINE_GRACE_DAYS - days_since_check
                    license_status.set(f"Valid - Offline grace: {remaining_offline} days")
                else:
                    license_status.set("Valid")
        else:
            license_status.set("Invalid or expired")
    else:
        license_status.set("No license")


# Hide main window until license is valid (online only)
root = tk.Tk()
root.withdraw()

license_status = tk.StringVar()
update_license_status()

if not is_license_valid_online():
    show_license_window()
    if not is_license_valid_online():
        exit()
else:
    root.deiconify()

# Start periodic license re-check in background
threading.Thread(target=periodic_license_check, daemon=True).start()





# --- Advanced License Key Demonstration UI ---
try:
    import qrcode
    from PIL import Image, ImageTk
    QR_AVAILABLE = True
except ImportError:
    QR_AVAILABLE = False

root.title("Advanced License Key Demo")
root.configure(bg="#f0f4f8")

# Set default font
try:
    import tkinter.font as tkfont
    default_font = tkfont.nametofont("TkDefaultFont")
    default_font.configure(size=11, family="Segoe UI")
except Exception:
    pass

# Title label
title_label = tk.Label(root, text="Advanced License Key Demo", font=("Segoe UI", 18, "bold"), fg="#2d415a", bg="#f0f4f8")
title_label.pack(pady=(18, 8))

# License status bar (top right) with visual indicator
status_frame = tk.Frame(root, bg="#f0f4f8")
status_frame.pack(fill="x", padx=10, pady=(0, 8))

def get_status_color():
    status = license_status.get().lower()
    if "valid" in status and "expired" not in status:
        return "#43a047"  # green
    elif "expir" in status:
        return "#ffa000"  # orange
    elif "no license" in status:
        return "#bdbdbd"  # gray
    else:
        return "#e53935"  # red

status_dot = tk.Canvas(status_frame, width=16, height=16, bg="#f0f4f8", highlightthickness=0)
dot = status_dot.create_oval(3, 3, 13, 13, fill=get_status_color(), outline="")
status_dot.pack(side="right", padx=(0, 4))
status_label = tk.Label(status_frame, textvariable=license_status, fg="#00796b", bg="#f0f4f8", anchor="e", font=("Segoe UI", 10, "italic"))
status_label.pack(side="right")

def update_status_dot():
    status_dot.itemconfig(dot, fill=get_status_color())
    root.after(1000, update_status_dot)
update_status_dot()

# Main license demo frame
main_frame = tk.Frame(root, bg="#ffffff", bd=2, relief="groove")
main_frame.pack(padx=18, pady=8, fill="both", expand=True)

# Hardware ID display with QR code
tk.Label(main_frame, text="Your Hardware ID:", font=("Segoe UI", 11, "bold"), bg="#ffffff").pack(pady=(18, 2))
hwid_str = get_hardware_id()
hwid_entry = tk.Entry(main_frame, font=("Segoe UI", 11), width=48, bd=2, relief="ridge", justify="center")
hwid_entry.insert(0, hwid_str)
hwid_entry.config(state="readonly", fg="#1976d2")
hwid_entry.pack(pady=(0, 6))

def copy_hwid():
    root.clipboard_clear()
    root.clipboard_append(hwid_str)
    messagebox.showinfo("Copied", "Hardware ID copied to clipboard.")

tk.Button(main_frame, text="Copy Hardware ID", command=copy_hwid, font=("Segoe UI", 10, "bold"), bg="#1976d2", fg="#fff", activebackground="#1565c0", activeforeground="#fff", bd=0, relief="ridge", width=20).pack(pady=(0, 6))

# QR code for hardware ID
if QR_AVAILABLE:
    qr_img = qrcode.make(hwid_str)
    qr_img = qr_img.resize((90, 90))
    qr_photo = ImageTk.PhotoImage(qr_img)
    qr_label = tk.Label(main_frame, image=qr_photo, bg="#ffffff")
    qr_label.pack(pady=(0, 8))
else:
    qr_label = tk.Label(main_frame, text="(Install 'qrcode' and 'Pillow' for QR code)", font=("Segoe UI", 9, "italic"), bg="#ffffff", fg="#bdbdbd")
    qr_label.pack(pady=(0, 8))

# License key entry
tk.Label(main_frame, text="Enter License Key:", font=("Segoe UI", 11, "bold"), bg="#ffffff").pack(pady=(8, 2))
license_var = tk.StringVar()
license_entry = tk.Entry(main_frame, font=("Segoe UI", 11), width=48, bd=2, relief="ridge", textvariable=license_var, justify="center")
license_entry.pack(pady=(0, 4))

def copy_license_key():
    val = license_var.get().strip()
    if val:
        root.clipboard_clear()
        root.clipboard_append(val)
        messagebox.showinfo("Copied", "License Key copied to clipboard.")
    else:
        messagebox.showwarning("No Key", "No license key to copy.")

tk.Button(main_frame, text="Copy License Key", command=copy_license_key, font=("Segoe UI", 9, "bold"), bg="#0288d1", fg="#fff", activebackground="#0277bd", activeforeground="#fff", bd=0, relief="ridge", width=16).pack(pady=(0, 8))

def submit_demo_key():
    user_key = license_var.get().strip()
    if not user_key:
        messagebox.showerror("Input Error", "Please enter a license key.")
        return
    # Try online activation first
    try:
        resp = requests.post(
            SERVER_URL,
            json={"hardware_id": hwid_str, "license_key": user_key},
            timeout=5
        )
        data = resp.json()
        if data.get('status') == 'ok':
            with open(LICENSE_FILE, 'w') as f:
                f.write(encrypt_license(user_key))
            save_last_check_time()  # Save successful activation time
            logging.info(f"License activated for HWID {hwid_str}")
            messagebox.showinfo("License", "License key accepted and activated online.")
            update_license_status()
        else:
            logging.warning(f"Activation failed for HWID {hwid_str}: {data.get('message')}")
            messagebox.showerror("License Error", data.get('message', 'Activation failed.'))
            update_license_status()
    except Exception as e:
        logging.error(f"Activation server error: {e}")
        messagebox.showerror("License Error", "Could not connect to activation server.\n\nTip: Check your internet connection or server status.")
        update_license_status()

tk.Button(main_frame, text="Submit License Key", command=submit_demo_key, font=("Segoe UI", 11, "bold"), bg="#388e3c", fg="#fff", activebackground="#2e7031", activeforeground="#fff", bd=0, relief="ridge", width=24).pack(pady=(0, 8))

# License expiry countdown
expiry_var = tk.StringVar()
expiry_label = tk.Label(main_frame, textvariable=expiry_var, font=("Segoe UI", 10, "italic"), bg="#ffffff", fg="#d84315")
expiry_label.pack(pady=(0, 8))

def update_expiry_countdown():
    if os.path.exists(LICENSE_FILE):
        with open(LICENSE_FILE, 'r') as f:
            lic = f.read().strip()
        expiry = get_license_expiry(lic)
        if expiry:
            now = datetime.datetime.now()
            delta = expiry - now
            if delta.days < 0:
                expiry_var.set(f"License expired on {expiry.date()}")
            else:
                expiry_var.set(f"License expires in {delta.days} days ({expiry.date()})")
        else:
            expiry_var.set("")
    else:
        expiry_var.set("")
    root.after(3000, update_expiry_countdown)
update_expiry_countdown()

# License info display
def show_license_info():
    lic = ""
    expiry = ""
    if os.path.exists(LICENSE_FILE):
        with open(LICENSE_FILE, 'r') as f:
            lic = f.read().strip()
        expiry_date = get_license_expiry(lic)
        if expiry_date:
            expiry = expiry_date.date()
    info = f"Hardware ID: {hwid_str}\nLicense Key: {lic}\nStatus: {license_status.get()}"
    if expiry:
        info += f"\nExpiry Date: {expiry}"
    messagebox.showinfo("License Info", info)

tk.Button(main_frame, text="Show License Info", command=show_license_info, font=("Segoe UI", 10, "bold"), bg="#0288d1", fg="#fff", activebackground="#0277bd", activeforeground="#fff", bd=0, relief="ridge", width=20).pack(pady=(0, 6))

# Check license online button
def check_license_online():
    if is_license_valid_online():
        messagebox.showinfo("License Check", "License is valid (checked online).")
    else:
        messagebox.showerror("License Check", "License is invalid or expired (checked online).")
    update_license_status()

tk.Button(main_frame, text="Check License Online", command=check_license_online, font=("Segoe UI", 10, "bold"), bg="#7b1fa2", fg="#fff", activebackground="#4a148c", activeforeground="#fff", bd=0, relief="ridge", width=20).pack(pady=(0, 8))

# Help/info section
def show_help():
    msg = (
        "Advanced License Key Demonstration\n\n"
        "1. Copy your Hardware ID using the button above or scan the QR code.\n"
        "2. Send your Hardware ID to the software provider.\n"
        "3. The provider will send you a license key.\n"
        "4. Enter the license key and click Submit.\n\n"
        "Features:\n"
        "- Hardware-locked license\n"
        "- Online activation and periodic re-check\n"
        "- Encrypted local license file\n"
        "- Expiry countdown\n"
        "- Visual status indicator\n"
        "- QR code for easy HWID transfer\n"
        "- Copy buttons for HWID and license key\n"
        "- Online license check\n\n"
        "Install 'qrcode' and 'Pillow' for QR code support."
    )
    messagebox.showinfo("How to use this Demo", msg)

tk.Button(main_frame, text="How to use this Demo", command=show_help, font=("Segoe UI", 10, "bold"), bg="#ffa000", fg="#fff", activebackground="#ff8f00", activeforeground="#fff", bd=0, relief="ridge", width=20).pack(pady=(0, 18))

root.minsize(520, 540)
root.mainloop()
