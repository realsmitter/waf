import time
from collections import defaultdict
from mitmproxy import http

# Import the variables module instead of individual variables
import variables
from persistence.ip_blocking import is_ip_blocked_for_domain, block_ip_for_domain
from detection.login_detection import is_login_request, is_failed_login, record_failed_login, get_domain

def is_standard_cookie_format(cookie_value):
    """
    Returns True if the cookie value appears to be in standard format without malicious code
    """
    # If the cookie contains obvious shell commands, return False
    for term in variables.SUSPICIOUS_COOKIE_TERMS:
        if term in cookie_value.lower():
            return False
            
    # Otherwise, consider it a legitimate cookie
    return True

def check_brute_force(flow):
    """
    Tracks login attempts and checks if the current IP should be blocked
    Returns True if the IP should be blocked
    """
    client_ip = flow.client_conn.address[0]
    domain = get_domain(flow)
    
    # ALWAYS log the current state for debugging
    print(f"BRUTE FORCE CHECK for IP {client_ip} on domain {domain} - URL: {flow.request.url}")
    
    # Check if the IP is already blocked for this domain
    is_blocked, time_left = is_ip_blocked_for_domain(client_ip, domain)
    if is_blocked:
        print(f"IP {client_ip} is BLOCKED for domain {domain}. Time remaining: {time_left} seconds")
        return True, f"Too many failed login attempts on {domain}. Try again in {time_left} seconds."
    
    # For login requests, we only track attempts - blocking will be done after response
    if is_login_request(flow):
        return False, ""
    
    return False, ""

def handle_login_response(flow):
    """
    Process login responses to track failed attempts
    """
    if not is_login_request(flow):
        return
    
    client_ip = flow.client_conn.address[0]
    domain = get_domain(flow)
    
    print(f"Processing login response for IP: {client_ip} on domain: {domain}")
    
    # Log the credentials being used (for debugging)
    if flow.request.urlencoded_form:
        username = flow.request.urlencoded_form.get("username", "") or flow.request.urlencoded_form.get("email", "")
        has_password = bool(flow.request.urlencoded_form.get("password", ""))
        print(f"Login attempt with username/email: '{username}', password provided: {has_password}")
    
    # Check if this is a failed login
    failed = is_failed_login(flow)
    print(f"Login result: {'FAILED' if failed else 'SUCCESS'}")
    
    if failed:
        # Record the failed login and get the current count
        recent_attempts = record_failed_login(flow)
        
        # Check if we've exceeded the threshold and IP blocking is enabled
        # Always use the current value of ENABLE_IP_BLOCKING
        if recent_attempts >= variables.MAX_LOGIN_ATTEMPTS and variables.ENABLE_IP_BLOCKING:
            # Block the IP for this domain
            block_ip_for_domain(client_ip, domain)
            # Modify the response to notify the user
            flow.response = http.Response.make(
                429, 
                f"<html><body><h1>429 Too Many Requests</h1><p>Too many failed login attempts on {domain}. Your IP has been blocked for {int(variables.LOGIN_BLOCK_DURATION*1)} seconds.</p></body></html>".encode(),
                {"Content-Type": "text/html"}
            )
            print(f"BLOCKED: Too many failed login attempts from IP: {client_ip} on domain: {domain}")
        elif recent_attempts >= variables.MAX_LOGIN_ATTEMPTS:
            # IP blocking is disabled, but we still want to log the excessive attempts
            print(f"IP blocking disabled: Not blocking IP {client_ip} despite {recent_attempts} failed attempts")
    else:
        print(f"Login appears successful for IP: {client_ip} on domain: {domain}")
