from concurrent.futures import ThreadPoolExecutor
from http.server import BaseHTTPRequestHandler
from pathlib import Path
import shutil
import socket
import ssl
import subprocess
import sys
import tempfile
import threading
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "app"))
import server


class ProbeHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-Length", "2")
        self.end_headers()
        self.wfile.write(b"ok")

    def log_message(self, *args):
        pass


@unittest.skipUnless(shutil.which("openssl"), "openssl needed for ephemeral test certificate")
class HttpsTest(unittest.TestCase):
    def test_idle_handshakes_do_not_block_other_clients(self):
        with tempfile.TemporaryDirectory() as directory:
            key, cert = Path(directory, "key.pem"), Path(directory, "cert.pem")
            subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
                            "-keyout", str(key), "-out", str(cert), "-days", "1",
                            "-subj", "/CN=localhost"], check=True, capture_output=True)
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            context.load_cert_chain(cert, key)
            with patch.object(server, "TLS_HANDSHAKE_TIMEOUT", 2):
                httpd = server.Server(("127.0.0.1", 0), ProbeHandler, tls_context=context)
                thread = threading.Thread(target=httpd.serve_forever, daemon=True)
                thread.start()
                idle = []
                try:
                    for _ in range(8):
                        idle.append(socket.create_connection(httpd.server_address, timeout=2))
                    client = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                    client.check_hostname = False
                    client.verify_mode = ssl.CERT_NONE  # ephemeral fixture only

                    def fetch(_):
                        with socket.create_connection(httpd.server_address, timeout=1) as raw:
                            with client.wrap_socket(raw, server_hostname="localhost") as tls:
                                tls.sendall(b"GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
                                response = b""
                                while True:
                                    part = tls.recv(4096)
                                    if not part:
                                        break
                                    response += part
                                self.assertIn(b"200 OK", response)
                                self.assertTrue(response.endswith(b"ok"))

                    with ThreadPoolExecutor(max_workers=4) as workers:
                        list(workers.map(fetch, range(4)))
                    # Each idle peer is also closed after the handshake deadline.
                    idle[0].settimeout(3)
                    self.assertEqual(idle[0].recv(1), b"")
                finally:
                    for connection in idle:
                        connection.close()
                    httpd.shutdown()
                    httpd.server_close()
                    thread.join(timeout=2)


if __name__ == "__main__":
    unittest.main()
