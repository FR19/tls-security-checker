import logging
from .tls_checker import TLSChecker

logger = logging.getLogger(__name__)

class CheckStaticKey(TLSChecker):
    def __init__(self, hostname, port, tls_ciphers, logger):
        super().__init__(hostname, port, logger)
        self.tls_ciphers = tls_ciphers

    def run_check(self):
        self.logger.info("Checking for usage of static key ciphers...")
        vulnerable = False
        for tls_version, cipher in self.tls_ciphers.items():
            static = [i for i in cipher if i.startswith("TLS_RSA_WITH")]
            if static:
                self.logger.warning(f"[!] Static Key Ciphers detected ({tls_version})")
                self.logger.debug(f'[+] Ciphers: {",".join(static)}')
                vulnerable = True
        
        if not vulnerable:
            self.logger.info("No Static Key Ciphers Used. All Good!!!")