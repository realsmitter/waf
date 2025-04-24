import re
from urllib.parse import urlparse
from collections import defaultdict
import time
import variables  # Import the module instead of individual variables

# Patterns to identify login requests and failed logins
LOGIN_URL_PATTERNS = [
    r"\/login",
    r"\/signin",
    r"\/auth",
    r"\/account\/login",
    r"\/realms\/[^/]+\/login-actions\/authenticate",  # Keycloak login pattern
    r"\/guacamole\/api\/tokens",                      # Guacamole login endpoint
    r"\/customer-identity\/login"                    # Generic login endpoint
]

# Common error messages that indicate failed logins (more generic)
FAILED_LOGIN_PATTERNS = [
    "incorrect password",
    "invalid password",
    "password incorrect",
    "wrong password",
    "invalid username",
    "invalid credentials",
    "authentication failed",
    "login failed",
    "bad credentials",
    "user not found",
    "account not found",
    "password error",
    "passwort falsch", 
    "login fehlgeschlagen"
]

# Data structures to track login attempts
login_attempts = defaultdict(list)  # (IP, domain) -> List of timestamp of login attempts

def get_domain(flow):
    """
    Extract the domain from the request URL
    """
    parsed_url = urlparse(flow.request.url)
    return parsed_url.netloc

def is_login_request(flow):
    """
    Checks if the request is a login attempt based on URL patterns and HTTP method
    """
    if flow.request.method != "POST":
        return False
    
    url = flow.request.url.lower()
    for pattern in LOGIN_URL_PATTERNS:
        if re.search(pattern, url, re.IGNORECASE):
            # Debug output for login detection with additional details
            print(f"LOGIN REQUEST DETECTED: {flow.request.url}")
            if flow.request.urlencoded_form:
                print(f"LOGIN FORM DATA: {dict(flow.request.urlencoded_form)}")
            return True
    return False

def is_failed_login(flow):
    """
    Checks if a login attempt has failed based on the response status and content
    Uses generic patterns that work across most websites
    """
    # First check if this is a login request
    if not is_login_request(flow):
        return False
    
    # Enhanced debugging
    print(f"Analyzing login response: Status {flow.response.status_code}, URL: {flow.request.url}")
    
    # Generic detection method #1: Check for HTTP status codes
    # A successful login typically redirects (302, 303, 307) or returns 200
    # Failed logins often return 401, 403, or 200 with an error message
    if flow.response.status_code in [401, 403]:
        print(f"FAILED LOGIN: Status code indicates failure: {flow.response.status_code}")
        return True
        
    # Generic detection method #2: Check for redirects back to login page
    if flow.response.status_code in [301, 302, 303, 307, 308]:
        location = flow.response.headers.get("location", "").lower()
        # If redirected back to login page, it's likely a failed login
        if any(pattern.strip('/') in location for pattern in ['/login', '/signin', '/auth']):
            print(f"FAILED LOGIN: Redirected back to login page: {location}")
            return True
    
    # Generic detection method #3: Check response content for common error messages
    if flow.response.text:
        response_text = flow.response.text.lower()
        for pattern in FAILED_LOGIN_PATTERNS:
            if pattern.lower() in response_text:
                print(f"FAILED LOGIN: Error message detected: '{pattern}'")
                return True
    
    # Generic detection method #4: Check for empty password submissions
    # This is a common reconnaissance technique
    if flow.request.urlencoded_form:
        username = flow.request.urlencoded_form.get("username", "") or flow.request.urlencoded_form.get("email", "")
        password = flow.request.urlencoded_form.get("password", "")
        
        if username and not password:
            print(f"POTENTIAL FAILED LOGIN: Empty password for username/email '{username}'")
            return True
    
    return False

def record_failed_login(flow):
    """
    Record a failed login attempt
    """
    client_ip = flow.client_conn.address[0]
    domain = get_domain(flow)
    ip_domain_key = (client_ip, domain)
    
    # Record the timestamp of the failed login attempt
    current_time = time.time()
    login_attempts[ip_domain_key].append(current_time)
    
    # Clean up old login attempts - always use current value
    login_attempts[ip_domain_key] = [t for t in login_attempts[ip_domain_key] 
                                    if current_time - t < variables.LOGIN_ATTEMPT_TIMEOUT]
    
    recent_attempts = len(login_attempts[ip_domain_key])
    print(f"FAILED LOGIN recorded for IP {client_ip} on domain {domain}. Total attempts: {recent_attempts}")
    
    return recent_attempts
