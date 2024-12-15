from os import unlink
from .tls_checker import TLSChecker
import subprocess
import xml.etree.ElementTree as ET

class CheckTLSVersionsAndCiphers(TLSChecker):
    def parse_nmap_tls(self, file_path):
        """
        Parse an Nmap XML file to extract supported TLS versions and ciphers.

        Args:
            file_path (str): Path to the Nmap XML file.

        Returns:
            dict: A dictionary with TLS versions as keys and lists of supported ciphers as values.
        """
        tls_data = {}

        try:
            tree = ET.parse(file_path)
            root = tree.getroot()

            # Iterate over host elements
            for host in root.findall("host"):
                # Iterate over port elements within the host
                for port in host.findall("ports/port"):
                    for script in port.findall("script"):
                        if script.get("id") == "ssl-enum-ciphers":
                            for child in script.findall("table"):
                                tls_version = child.get("key")
                                if tls_version and tls_version.startswith("TLSv"):
                                    ciphers = []
                                    for cipher_table in child.findall("table[@key='ciphers']"):
                                        for cipher_name in cipher_table.findall("table/elem[@key='name']"):
                                            if cipher_name is not None:
                                                ciphers.append(cipher_name.text)

                                    if tls_version not in tls_data:
                                        tls_data[tls_version] = []

                                    tls_data[tls_version].extend(ciphers)
        except ET.ParseError as e:
            self.logger.debug(f"Error parsing XML: {e}")
        except Exception as e:
            self.logger.debug(f"Unexpected error: {e}")

        return tls_data
    
    def get_ciphers(self):
        try:
            command = [
                "nmap", "-Pn" ,"--script", "ssl-enum-ciphers",
                "-p", f"{self.port}",
                "-oX", "tmp_result.xml",
                f"{self.hostname}"
            ]

            output = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            if output.stderr:
                self.logger.debug(f"Subprocess Error: {output.stderr}")
    
            ciphers = self.parse_nmap_tls("tmp_result.xml")
            unlink("tmp_result.xml")
            return ciphers
        except Exception as e:
            self.logger.debug(e)
            return False
        
    def run_check(self):
        self.logger.info("Checking for supported TLS Versions and Ciphers...")
        ciphers = self.get_ciphers()
        self.logger.info(f"Supported TLS versions: {', '.join(ciphers.keys())}")
        return ciphers
