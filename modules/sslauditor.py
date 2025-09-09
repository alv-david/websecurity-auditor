import ssl
import socket

def check_tls_version(host, port=443):
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((host, port), timeout=5) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as sslsock:
                return sslsock.version()
    except:
        return "ERR_NO_TLS"
