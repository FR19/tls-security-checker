import logging
from .tls_checker import TLSChecker

logger = logging.getLogger(__name__)

class CheckStrongCipher(TLSChecker):
    def __init__(self, hostname, port, tls_ciphers, logger):
        super().__init__(hostname, port, logger)
        self.tls_ciphers = tls_ciphers

    def run_check(self):
        self.logger.info("Checking for usage of strong ciphers...")
        vulnerable = False
        for tls_version, cipher in self.tls_ciphers.items():
            strong = [i for i in cipher if i.startswith("TLS_DHE") or i.startswith("TLS_ECDHE") or "GCM" in i or "CHACHA20_POLY1305" in i]
            if not strong:
                self.logger.warning(f"[!] No strong ciphers supported ({tls_version})")
                vulnerable = True
        
        if not vulnerable:
            self.logger.info("Found Usage of Strong Cipher. All Good!!!")