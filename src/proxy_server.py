import asyncio
from proxy_runner import start_proxy
import sys
import os
import variables
from web_interface import run_web_interface

# Ensure that the module path is correct
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

if __name__ == "__main__":
    # Start the web interface only if enabled
    if variables.ENABLE_WEBINTERFACE:
        print("Starting web interface on port 80 (ENABLE_WEBINTERFACE=True)")
        web_thread = run_web_interface()
    else:
        print("Web interface disabled (ENABLE_WEBINTERFACE=False)")
    
    # Start the proxy in the main thread
    asyncio.run(start_proxy())
