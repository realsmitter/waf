import re
from urllib.parse import unquote

# SQL Injection Patterns
SQL_INJECTION_PATTERNS = [
    r"(\b|')OR(\b|'|\s+).*?(\b|')=(\b|'|\s+).*?(\b|')",  # OR 1=1
    r"(\b|')AND(\b|'|\s+).*?(\b|')=(\b|'|\s+).*?(\b|')",  # AND 1=1
    r"--",                                             # SQL comment
    r";\s*(SELECT|INSERT|UPDATE|DELETE|DROP|ALTER|CREATE)",  # SQL command chaining
    r"UNION\s+(ALL\s+)?SELECT",                       # UNION injection
    r"SELECT\s+.*\s+FROM",                            # Direct SELECT statement
    r"INSERT\s+INTO",                                 # Direct INSERT statement
    r"UPDATE\s+.*\s+SET",                             # Direct UPDATE statement 
    r"DELETE\s+FROM",                                 # Direct DELETE statement
    r"DROP\s+TABLE",                                  # DROP TABLE statement
    r"EXEC\s+(xp|sp)_",                               # Stored procedure execution
    r"WAITFOR\s+DELAY",                               # Time-based SQL injection
    r"(ORDER|GROUP)\s+BY\s+\d+",                      # ORDER/GROUP BY injection
    r"HAVING\s+\d+=\d+",                              # HAVING injection
    r"\bSLEEP\s*\(\s*\d+\s*\)",                       # MySQL SLEEP function
    r"\bBENCHMARK\s*\(",                              # MySQL BENCHMARK function
    r"\bLOAD_FILE\s*\(",                              # MySQL file access
    r"/\*.*\*/",                                      # C-style comment
]

def detect_sql_injection(text):
    """
    Check text for SQL injection patterns
    Returns True if SQL injection is detected
    """
    if text is None:
        return False
        
    # URL-decode the text to catch encoded injection attempts
    decoded_text = unquote(text)
    
    for pattern in SQL_INJECTION_PATTERNS:
        if re.search(pattern, decoded_text, re.IGNORECASE):
            return True
    return False
