from urllib.parse import unquote

def detect_test_string(text):
    """
    Check if the text contains the 'teststring' marker
    Returns True if the test string is detected
    """
    if text is None:
        return False
        
    # URL-decode the text to catch encoded test strings
    decoded_text = unquote(text).lower()
    
    # Simple check for 'teststring'
    return 'teststring' in decoded_text
