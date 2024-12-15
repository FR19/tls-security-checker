import logging
from .tls_checker import TLSChecker
import subprocess
import json
from os import unlink

logger = logging.getLogger(__name__)

class CheckVulnerability(TLSChecker):
    def __init__(self, hostname, port, tls_ciphers, logger):
        super().__init__(hostname, port, logger)
        self.tls_ciphers = tls_ciphers

    def run_check(self):
        self.logger.info("Checking for common vulnerability...")
        command = [
            "testssl.sh", "-U",
            "-oj", "tmp_result.json",
            f"{self.hostname}:{self.port}"
        ]
        output = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        if output.stderr:
            self.logger.debug(f"Subprocess Error: {output.stderr}")
        

        with open("tmp_result.json") as f:
            vuln = json.load(f)
        
        unlink("tmp_result.json")

        valid_vuln = list(filter(lambda x: x["severity"] not in ["OK", "INFO", "WARN"], vuln))
        if valid_vuln:
            for v in valid_vuln:
                self.logger.warning(f"[!] Target vulnerable to {v['id']} ({v.get('cve')}) - {v['severity']}")
                self.logger.debug(f"[+] {v['finding']}")

            return
        
        self.logger.info("No Vulnerability discovered. All Good!!!")