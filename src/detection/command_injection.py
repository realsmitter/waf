import re
from urllib.parse import unquote

# Command Injection Patterns
COMMAND_INJECTION_PATTERNS = [
    r";\s*(cat|ls|pwd|rm|echo|bash|sh)\s",             # More specific command chaining with semicolon
    r"\|\s*(cat|ls|pwd|rm|echo|bash|sh)\s",            # More specific pipe to dangerous command
    r"&&\s*(cat|ls|pwd|rm|echo|bash|sh)\s",            # More specific command chaining with &&
    r"`(cat|ls|pwd|rm|echo|bash).*`",               # More specific backtick execution
    r"\$\((cat|ls|pwd|rm|echo|bash).*\)",           # More specific command substitution $(...)
    r">\s*/[a-zA-Z0-9_/]+",                           # Output redirection to specific path
    r">>\s*/[a-zA-Z0-9_/]+",                          # Output append to specific path
    r"<\s*/[a-zA-Z0-9_/]+",                           # Input from file with specific path
    r"cat\s+/[a-zA-Z0-9_/]+",                         # Reading specific files
    r"wget\s+http",                                   # Specific download command
    r"curl\s+http",                                   # Specific download with curl
    r"ping\s+-[a-z]*c",                               # Network probing with count
    r"nc\s+-[a-z]*v",                                 # Netcat with specific flags
    r"nmap\s+-[a-z]*p",                               # Network scanning specific ports
    r"rm\s+(-rf\s+)?/[a-zA-Z0-9_/]+",                 # More specific file deletion
    r"chmod\s+[0-7]{3,4}\s+",                         # More specific chmod command
    r"chown\s+[a-zA-Z0-9_]+:[a-zA-Z0-9_]+\s+",        # More specific chown command
    r"cd\s+/[a-zA-Z0-9_/]+"                           # More specific directory traversal
]

# Add a list of common user agents to whitelist
COMMON_USER_AGENTS = [
    r"Mozilla/5\.0 \(Windows NT",
    r"Mozilla/5\.0 \(Macintosh",
    r"Mozilla/5\.0 \(X11",
    r"Mozilla/5\.0 \(Linux",
    r"Mozilla/5\.0 \(Android",
    r"Mozilla/5\.0 \(iPhone",
    r"Mozilla/5\.0 \(iPad",
    r"Chrome/\d+",
    r"Firefox/\d+",
    r"Safari/\d+",
    r"Edge/\d+",
    r"Opera/\d+",
    r"Trident/\d+",
    r"MSIE \d+",
    r"Gecko/\d+"
]

def is_common_user_agent(text):
    """
    Checks if the text matches a common user agent pattern
    """
    if text is None:
        return False
        
    for pattern in COMMON_USER_AGENTS:
        if re.search(pattern, text, re.IGNORECASE):
            return True
    return False

def detect_command_injection(text, is_user_agent=False):
    """
    Check text for command injection attacks
    """
    if text is None:
        return False
    
    # Skip checks for common user agents
    if is_user_agent and is_common_user_agent(text):
        return False
    
    # URL-decode the text to catch encoded attacks
    decoded_text = unquote(text)
    
    for pattern in COMMAND_INJECTION_PATTERNS:
        if re.search(pattern, decoded_text, re.IGNORECASE):
            return True
    return False
