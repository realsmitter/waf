import asyncio
import os
from mitmproxy import options
from mitmproxy.tools.dump import DumpMaster
from log_handler import clear_logs, ProxyAddOn

async def start_proxy():
    """
    Starts the Mitmproxy with the appropriate settings.
    """

    clear_logs()


    opts = options.Options(
        listen_host="0.0.0.0",
        listen_port=8080,
        ssl_insecure=False,
    )

    proxy = DumpMaster(opts)
    proxy.addons.add(ProxyAddOn())

    try:
        print("Starting proxy on port 8080...")
        await proxy.run()
    except KeyboardInterrupt:
        print("Shutting down proxy...")
        proxy.shutdown()
