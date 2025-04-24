# System Paths
REQUEST_LOG_PATH = "/app/log/log_requests.txt"
RESPONSE_LOG_PATH = "/app/log/log_responses.txt"
BLOCKED_IPS_FILE = "/app/log/blocked_ips.json"

# System Settings
CLEAR_LOGS_ON_START = True
ENABLE_LOGGING = False  # By default, don't write log files
ENABLE_IP_BLOCKING = True  # By default, block IPs for brute force attacks
ENABLE_WEBINTERFACE = False  # By default, start the web interface

# Security Settings
# Brute Force Protection
MAX_LOGIN_ATTEMPTS = 5  # Number of failed attempts before blocking
LOGIN_ATTEMPT_TIMEOUT = 600  # 5 minutes - window for counting attempts
LOGIN_BLOCK_DURATION = 30  # 30 seconds - how long IPs stay blocked

# Detection Patterns
SUSPICIOUS_COOKIE_TERMS = ['cat ', 'rm -', 'wget ', 'curl ', 'bash ', '/etc/', '/bin/', '/tmp/']
