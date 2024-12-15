from .tls_checker import TLSChecker

class CheckCommonPrime(TLSChecker):
    PRIMES_URL = "https://testssl.sh/etc/common-primes.txt"

    def __init__(self, hostname, port, tls_ciphers, logger):
        super().__init__(hostname, port, logger)
        self.tls_ciphers = tls_ciphers

    def fetch_common_primes(self):
        import requests
        try:
            response = requests.get(self.PRIMES_URL)
            response.raise_for_status()
            primes = set()
            for line in response.text.splitlines():
                line = line.strip()
                if line and not line.startswith("#"):
                    primes.add(line.lower())
            return primes
        except Exception as e:
            self.logger.error(f"Error fetching common primes: {e}")
            return set()

    def run_check(self):
        self.logger.info("Checking for common prime...")
        common_primes = self.fetch_common_primes()
        vulnerable = False
        for tls_version in self.tls_ciphers.keys():
            raw_data = self.get_server_key_exchange_bytes(tls_version)
            if not raw_data:
                continue

            prime = self.parse_server_key_exchange(raw_data)
            if prime and prime.strip().lower() in common_primes:
                self.logger.warning(f"[!] Common Prime detected ({tls_version})")
                self.logger.debug(f"[+] Prime Number: {prime}")
                vulnerable = True
        
        if not vulnerable:
            self.logger.info("No Common Prime detected. All Good!!!")