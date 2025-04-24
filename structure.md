./<Working Directory>
├── .mitmproxy/
│   ├── mitmproxy-ca-cert.cer
│   ├── mitmproxy-ca-cert.p12
│   ├── mitmproxy-ca-cert.pem
│   ├── mitmproxy-ca.p12
│   ├── mitmproxy-ca.pem
│   └── mitmproxy-dhparam.pem
├── log/
│   ├── blocked_ips.json
│   ├── log_requests.txt
│   └── log_responses.txt
├── src/
│   ├── brute_force.py
│   ├── config.py
│   ├── log_handler.py
│   ├── proxy_runner.py
│   ├── proxy_server.py
│   ├── security_utils.py
│   ├── variables.py
│   ├── web_interface.py
│   ├── templates/
│   │   ├── blocked_ips.html
│   │   └── index.html
│   ├── detection/
│   │   ├── command_injection.py
│   │   ├── login_detection.py
│   │   ├── sql_injection.py
│   │   └── test_string.py
│   └── persistence/
│       └── ip_blocking.py
├── docker-compose.yml
├── Dockerfile
├── LICENSE
├── README.md
├── requirements.txt
└── structure.md