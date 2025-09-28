#!/usr/bin/env python3
"""
License Key Generator for Google Account Automation Tool
Generates license keys compatible with the Node.js activation server
"""

import hashlib
import hmac
from datetime import datetime, timedelta
import sys

# Must match the server.js SECRET_KEY (hex format for compatibility)
SECRET_KEY = "a1b2c3d4e5f67890abcdef1234567890abcdef1234567890abcdef1234567890"

def generate_license_signature(hardware_id, expiry_date):
    """Generate signature matching server.js logic"""
    # Reverse the hardware ID
    reversed_id = hardware_id[::-1]
    msg = f"{reversed_id}-{expiry_date}"
    
    # Create HMAC signature
    signature = hmac.new(SECRET_KEY.encode(), msg.encode(), hashlib.sha256).hexdigest()
    
    # Return first 16 characters (matching server logic)
    return signature[:16]

def generate_license_key(hardware_id, days_valid=365):
    """Generate a license key in the format expected by server.js"""
    # Calculate expiry date
    expiry_date = datetime.now() + timedelta(days=days_valid)
    expiry_string = expiry_date.strftime("%Y%m%d")
    
    # Reverse the hardware ID (matching server logic)
    reversed_hardware_id = hardware_id[::-1]
    
    # Generate signature
    signature = generate_license_signature(hardware_id, expiry_string)
    
    # Create license key in server expected format
    license_key = f"CALC-{reversed_hardware_id}-{expiry_string}-{signature}"
    
    return license_key, expiry_date.strftime("%Y-%m-%d")

def main():
    """Generate license key for a given hardware ID"""
    print("🔑 License Key Generator for Google Account Automation Tool")
    print("=" * 60)
    
    if len(sys.argv) > 1:
        hardware_id = sys.argv[1]
    else:
        hardware_id = input("Enter Hardware ID: ").strip()
    
    if not hardware_id:
        print("❌ Hardware ID is required!")
        return
    
    try:
        days = int(input("Enter validity period in days (default 365): ").strip() or "365")
    except ValueError:
        days = 365
    
    # Generate license key
    license_key, expiry_date = generate_license_key(hardware_id, days)
    
    print(f"")
    print(f"✅ License Key Generated Successfully!")
    print(f"=" * 60)
    print(f"Hardware ID: {hardware_id}")
    print(f"License Key: {license_key}")
    print(f"Expires: {expiry_date}")
    print(f"Valid for: {days} days")
    print(f"")
    print(f"📋 Copy this license key to your customer:")
    print(f"┌{'─' * (len(license_key) + 2)}┐")
    print(f"│ {license_key} │")
    print(f"└{'─' * (len(license_key) + 2)}┘")
    print(f"")

if __name__ == "__main__":
    main()