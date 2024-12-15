import logging
from .tls_checker import TLSChecker

logger = logging.getLogger(__name__)

class CheckWeakMACs(TLSChecker):
    def __init__(self, hostname, port, tls_ciphers, logger):
        super().__init__(hostname, port, logger)
        self.tls_ciphers = tls_ciphers

        
    def run_check(self):
        self.logger.info("Checking for Weak MACs...")
        vulnerable = False
        for tls_version, cipher in self.tls_ciphers.items():
            weak = [i for i in cipher if i.endswith("_SHA") or i.endswith("_SHA1") or i.endswith("_MD5")]
            if weak:
                self.logger.warning(f"[!!] Weak MACs detected ({tls_version})")
                self.logger.debug(f'Ciphers: {",".join(weak)}')
                vulnerable = True
        
        if not vulnerable:
            self.logger.info("All Good!!!")