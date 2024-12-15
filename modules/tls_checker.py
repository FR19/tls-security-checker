import subprocess
import re

class TLSChecker:
    def __init__(self, hostname, port, logger):
        self.hostname = hostname
        self.port = port
        self.tls_versions = ["TLSv1", "TLSv1.1", "TLSv1.2", "TLSv1.3"]
        self.logger = logger

    def get_server_key_exchange_bytes(self, tls_version):
        try:
            command = [
                "timeout", "3",
                "openssl", "s_client",
                "-cipher", "DHE",
                f"-{tls_version.lower().replace('.', '_').replace('v','')}",
                "-connect", f"{self.hostname}:{self.port}",
                "-msg",
                "-quiet"
            ]
            result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            data = re.findall(r"ServerKeyExchange(.*?)\n<<<", result.stdout, re.DOTALL)
            if data:
                return bytes.fromhex(data[0].replace(" ", "").strip())
        except Exception as e:
            self.logger.error(f"Error fetching ServerKeyExchange bytes: {e}")
        return None

    def parse_server_key_exchange(self, raw_data):
        try:
            offset = 0

            # Handshake Type
            handshake_type = raw_data[offset]
            offset += 1
            if handshake_type != 0x0C:
                self.logger.error("Not a ServerKeyExchange message.")
                return None

            # Handshake Length
            handshake_length = int.from_bytes(raw_data[offset:offset + 3], "big")
            offset += 3

            # Diffie-Hellman Prime (p)
            prime_length = int.from_bytes(raw_data[offset:offset + 2], "big")
            offset += 2
            prime = raw_data[offset:offset + prime_length]
            return prime.hex()
        except Exception as e:
            self.logger.error(f"Error parsing ServerKeyExchange: {e}")
        return None
