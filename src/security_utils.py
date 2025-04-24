from mitmproxy import http
from urllib.parse import parse_qs

from detection.sql_injection import detect_sql_injection
from detection.command_injection import detect_command_injection, is_common_user_agent
from detection.test_string import detect_test_string
from brute_force import check_brute_force, is_standard_cookie_format
from variables import SUSPICIOUS_COOKIE_TERMS

def apply_blocking_rules(flow):
    """
    Applies blocking rules to the request and returns True if the request should be blocked.
    """
    # First check raw URL for teststring (highest priority check)
    if detect_test_string(flow.request.url):
        flow.response = http.Response.make(
            403,
            b"<html><body><h1>403 Forbidden</h1><p>Test string detected in URL.</p></body></html>",
            {"Content-Type": "text/html"}
        )
        print(f"BLOCKED: Test string detected in URL: {flow.request.url}")
        return True
        
    # Check raw content string for teststring
    if flow.request.content:
        try:
            raw_content = flow.request.content.decode('utf-8', errors='ignore')
            if detect_test_string(raw_content):
                flow.response = http.Response.make(
                    403,
                    b"<html><body><h1>403 Forbidden</h1><p>Test string detected in request body.</p></body></html>",
                    {"Content-Type": "text/html"}
                )
                print(f"BLOCKED: Test string detected in raw content")
                return True
                
            # Parse form data if it's url-encoded
            if flow.request.headers.get("content-type", "") == "application/x-www-form-urlencoded":
                try:
                    form_data = parse_qs(raw_content)
                    for key, values in form_data.items():
                        for value in values:
                            if detect_test_string(value):
                                flow.response = http.Response.make(
                                    403,
                                    b"<html><body><h1>403 Forbidden</h1><p>Test string detected in form field.</p></body></html>",
                                    {"Content-Type": "text/html"}
                                )
                                print(f"BLOCKED: Test string detected in form field '{key}': {value}")
                                return True
                except Exception as e:
                    print(f"Error parsing form data: {e}")
        except Exception as e:
            print(f"Error decoding request content: {e}")

    # Debug output
    print(f"Checking request: {flow.request.method} {flow.request.url}")
    
    # First check for brute force attempts
    client_ip = flow.client_conn.address[0]
    should_block, message = check_brute_force(flow)
    if should_block:
        flow.response = http.Response.make(
            429, 
            f"<html><body><h1>429 Too Many Requests</h1><p>{message}</p></body></html>".encode(),
            {"Content-Type": "text/html"}
        )
        print(f"BLOCKED: Brute force attempt from IP: {client_ip}")
        return True
    
    # Check form data more reliably
    if hasattr(flow.request, 'urlencoded_form') and flow.request.urlencoded_form:
        for form_name, form_value in flow.request.urlencoded_form.items():
            if detect_sql_injection(form_value) or detect_command_injection(form_value):
                flow.response = http.Response.make(403, b"Forbidden: Possible injection attack detected in form data")
                print(f"BLOCKED: Injection attempt detected in form field '{form_name}': {form_value}")
                return True
            
            if detect_test_string(form_value):
                flow.response = http.Response.make(403, b"Forbidden: Test string detected in form data")
                print(f"BLOCKED: Test string detected in form field '{form_name}': {form_value}")
                return True

    # Check URL path
    url_path = flow.request.path
    if detect_sql_injection(url_path) or detect_command_injection(url_path):
        flow.response = http.Response.make(403, b"Forbidden: Possible injection attack detected in URL")
        print(f"BLOCKED: Injection attempt detected in URL: {url_path}")
        return True
    if detect_test_string(url_path):
        flow.response = http.Response.make(403, b"Forbidden: Test string detected in URL")
        print(f"BLOCKED: Test string detected in URL: {url_path}")
        return True
    
    # Check query parameters
    for param_name, param_value in flow.request.query.items():
        if detect_sql_injection(param_value) or detect_command_injection(param_value):
            flow.response = http.Response.make(403, b"Forbidden: Possible injection attack detected in query parameters")
            print(f"BLOCKED: Injection attempt detected in parameter '{param_name}': {param_value}")
            return True
        if detect_test_string(param_value):
            flow.response = http.Response.make(403, b"Forbidden: Test string detected in query parameters")
            print(f"BLOCKED: Test string detected in parameter '{param_name}': {param_value}")
            return True
    
    # Check headers with special handling for cookies and User-Agent
    for header, value in flow.request.headers.items():
        # Skip common headers that don't typically contain user input
        if header.lower() in ["accept", "accept-encoding", "accept-language", "connection", "cache-control"]:
            continue
            
        # Special handling for User-Agent
        if header.lower() == "user-agent":
            # Apply command injection check with user-agent flag
            if detect_command_injection(value, is_user_agent=True):
                flow.response = http.Response.make(403, b"Forbidden: Possible command injection in User-Agent")
                print(f"BLOCKED: Command injection in User-Agent: {value}")
                return True
            continue
            
        # Special handling for cookies
        if header.lower() == "cookie":
            if not is_standard_cookie_format(value):
                if detect_sql_injection(value):
                    flow.response = http.Response.make(403, b"Forbidden: Suspicious SQL pattern in cookies")
                    print(f"BLOCKED: Suspicious SQL pattern in cookies: {value[:100]}")
                    return True
                    
                for pattern in SUSPICIOUS_COOKIE_TERMS:
                    if pattern in value.lower():
                        flow.response = http.Response.make(403, b"Forbidden: Suspicious command in cookies")
                        print(f"BLOCKED: Suspicious command in cookies: {value[:100]}")
                        return True
            continue
        
        # Check remaining headers normally
        if detect_sql_injection(value):
            flow.response = http.Response.make(403, b"Forbidden: Possible SQL injection in headers")
            print(f"BLOCKED: SQL Injection in header '{header}': {value}")
            return True
            
        if detect_command_injection(value, is_user_agent=False):
            flow.response = http.Response.make(403, b"Forbidden: Possible command injection in headers")
            print(f"BLOCKED: Command Injection in header '{header}': {value}")
            return True
            
        if detect_test_string(value):
            flow.response = http.Response.make(403, b"Forbidden: Test string detected in headers")
            print(f"BLOCKED: Test string in header '{header}': {value}")
            return True
    
    # No injection detected, request not blocked
    return False
