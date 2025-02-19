import argparse
import logging
from modules.common_prime import CheckCommonPrime
from modules.tls_versions import CheckTLSVersionsAndCiphers
from modules.weak_macs import CheckWeakMACs
from modules.static_key import CheckStaticKey
from modules.strong_cipher import CheckStrongCipher
from modules.vulnerabilities_check import CheckVulnerability

# Configure logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")
logger = logging.getLogger(__name__)

CHECKERS = [CheckCommonPrime, CheckWeakMACs, CheckStaticKey, CheckStrongCipher, CheckVulnerability]

def main():
    parser = argparse.ArgumentParser(description="TLS Security Checker")
    parser.add_argument("-host", type=str, help="Target hostname")
    parser.add_argument("-port", type=int, help="Target port")
    parser.add_argument("-debug", action="store_true", help="Enable Debug Logging")
    args = parser.parse_args()

    hostname = args.host
    port = args.port

    if args.debug:
        logger.setLevel(logging.DEBUG)

    logger.info(f"==== Starting TLS checks on {hostname}:{port} ====")
    
    # Run TLS versions check and get all supported ciphers
    tls_versions_cipher_check = CheckTLSVersionsAndCiphers(hostname, port, logger)
    tls_ciphers = tls_versions_cipher_check.run_check()

    for checker in CHECKERS:
        obj = checker(hostname, port, tls_ciphers, logger)
        obj.run_check()

    logger.info(f"==== TLS checks completed for {hostname}:{port} ====")


if __name__ == "__main__":
    main()
