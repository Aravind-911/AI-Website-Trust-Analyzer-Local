import ssl
import socket
from urllib.parse import urlparse

def check_ssl(url):
    try:
        hostname = urlparse(url).netloc

        context = ssl.create_default_context()

        with socket.create_connection((hostname, 443), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=hostname):
                return True

    except Exception:
        return False