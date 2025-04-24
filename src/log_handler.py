import variables  # Import the module, not just the variable
from security_utils import apply_blocking_rules
from brute_force import handle_login_response, check_brute_force
from detection.login_detection import is_login_request, get_domain
from persistence.ip_blocking import is_ip_blocked_for_domain
from mitmproxy import http
import os

def clear_logs():
    """
    Clears the log files if `CLEAR_LOGS_ON_START` is set to True.
    """
    # Only clear logs if CLEAR_LOGS_ON_START is True
    if variables.CLEAR_LOGS_ON_START:
        print("Clearing existing logs (CLEAR_LOGS_ON_START=True)...")
        for log_path in [variables.REQUEST_LOG_PATH, variables.RESPONSE_LOG_PATH]:
            try:
                with open(log_path, "w") as log_file:
                    pass  # Create empty file
                print(f"Cleared log file: {log_path}")
            except Exception as e:
                print(f"Error clearing log file {log_path}: {e}")
    else:
        print("Skipping log clearing (CLEAR_LOGS_ON_START=False)")
        # Ensure log files exist but don't clear them
        for log_path in [variables.REQUEST_LOG_PATH, variables.RESPONSE_LOG_PATH]:
            try:
                if not os.path.exists(log_path):
                    os.makedirs(os.path.dirname(log_path), exist_ok=True)
                    with open(log_path, "a"):
                        pass  # Create empty file if it doesn't exist
                    print(f"Created log file: {log_path}")
            except Exception as e:
                print(f"Error creating log file {log_path}: {e}")

class ProxyAddOn:
    """
    Mitmproxy Add-on for logging requests and responses.
    """
    def request(self, flow):
        """
        Process incoming requests.
        Logs the request first and then blocks it if a rule applies.
        """
        # Only log the request if logging is enabled - always check the current value
        if variables.ENABLE_LOGGING:
            with open(variables.REQUEST_LOG_PATH, "a") as log_file:
                log_file.write(f"Request: {flow.request.method} {flow.request.url}\n")
                log_file.write(f"Header: {flow.request.headers}\n")
                log_file.write(f"Content: {flow.request.text}\n\n")
        
        # Always log to console for debugging
        print(f"Request: {flow.request.method} {flow.request.url}")

        # Check if IP is blocked for this domain (direct check)
        client_ip = flow.client_conn.address[0]
        domain = get_domain(flow)
        is_blocked, time_left = is_ip_blocked_for_domain(client_ip, domain)
        
        if is_blocked:
            print(f"REQUEST BLOCKED - IP {client_ip} is blocked for domain {domain}")
            flow.response = http.Response.make(
                429,
                f"<html><body><h1>429 Too Many Requests</h1><p>Your IP has been blocked for this domain due to too many failed login attempts. Try again in {time_left} seconds.</p></body></html>".encode(),
                {"Content-Type": "text/html"}
            )
            return

        # Special handling for login requests
        if is_login_request(flow):
            print(f"LOGIN REQUEST DETECTED in handler: {flow.request.url}")
            # For login requests, we'll delay the brute force check until response

        # Then check if the request should be blocked
        if apply_blocking_rules(flow):
            print("REQUEST BLOCKED - Returning 403 response")
            return  # The request was blocked and not forwarded

    def response(self, flow):
        """
        Process outgoing responses.
        """
        # Process the response for login attempt tracking
        if is_login_request(flow):
            print("Processing login response...")
            # Check if we should block due to brute force BEFORE handling the login attempt
            should_block, message = check_brute_force(flow)
            if should_block:
                print(f"BRUTE FORCE DETECTED - Blocking response")
                flow.response = http.Response.make(
                    429,
                    f"<html><body><h1>429 Too Many Requests</h1><p>{message}</p></body></html>".encode(),
                    {"Content-Type": "text/html"}
                )
                # Since we're blocking, we don't need to process the login response further
                return
                
            # Process the login response normally
            handle_login_response(flow)
            
        # Regular response logging only if enabled - always check the current value
        if variables.ENABLE_LOGGING:
            with open(variables.RESPONSE_LOG_PATH, "a") as log_file:
                log_file.write(f"Response: {flow.response.status_code} {flow.request.url}\n")
                log_file.write(f"Header: {flow.response.headers}\n")
                log_file.write(f"Content: {flow.response.text}\n\n")
        
        # Always log to console for debugging
        print(f"Response: {flow.response.status_code} {flow.request.url}")
