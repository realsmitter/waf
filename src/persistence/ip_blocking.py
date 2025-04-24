import time
import json
import os

# Import configuration
from variables import LOGIN_BLOCK_DURATION, BLOCKED_IPS_FILE, CLEAR_LOGS_ON_START

# In-memory cache of blocked IPs
blocked_ips = {}

def load_blocked_ips():
    """
    Load the blocked IPs from the JSON file
    """
    global blocked_ips
    
    # If CLEAR_LOGS_ON_START is True, initialize with empty dict instead of loading
    if CLEAR_LOGS_ON_START:
        print("Clearing blocked IPs list due to CLEAR_LOGS_ON_START=True")
        blocked_ips = {}
        save_blocked_ips()  # Save empty dict to clear the file
        return
    
    try:
        if os.path.exists(BLOCKED_IPS_FILE):
            with open(BLOCKED_IPS_FILE, 'r') as f:
                blocked_ips = json.load(f)
    except Exception as e:
        print(f"Error loading blocked IPs file: {e}")
        blocked_ips = {}

def save_blocked_ips():
    """
    Save the blocked IPs to the JSON file
    """
    try:
        with open(BLOCKED_IPS_FILE, 'w') as f:
            json.dump(blocked_ips, f)
    except Exception as e:
        print(f"Error saving blocked IPs file: {e}")

# Load blocked IPs on module import
load_blocked_ips()

def is_ip_blocked_for_domain(ip, domain):
    """
    Check if an IP is blocked for a specific domain
    Returns: (is_blocked, time_left_in_seconds)
    """
    key = f"{ip}:{domain}"
    if key in blocked_ips:
        block_time = blocked_ips[key]
        current_time = time.time()
        time_left = block_time - current_time
        
        if time_left > 0:
            return True, int(time_left)
        else:
            # Block expired, remove it
            del blocked_ips[key]
            save_blocked_ips()
            
    return False, 0

def block_ip_for_domain(ip, domain, duration=None):
    """
    Block an IP for a specific domain
    """
    if duration is None:
        duration = LOGIN_BLOCK_DURATION
        
    key = f"{ip}:{domain}"
    blocked_ips[key] = time.time() + duration
    print(f"IP {ip} blocked for domain {domain} for {duration} seconds")
    save_blocked_ips()
