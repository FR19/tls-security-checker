# TLS Security Checker

TLS Security Checker is a Python-based tool designed to analyze the security posture of TLS/SSL servers. It performs various checks, such as detecting weak ciphers, static key ciphers, and other common vulnerabilities in TLS configurations.

## Features

- Verifies supported TLS versions.
- Verifies usage of strong cipher.
- Detects the use of common Diffie-Hellman primes.
- Identifies weak MAC algorithms (e.g., MD5, SHA1).
- Checks for static key ciphers (`TLS_RSA_WITH_*`).
- Automates analysis of vulnerabilities using **testssl.sh**.

## Prerequisites

The following tools must be installed on your system:

1. **nmap**:

   - Used for enumerating ciphers and protocols.
   - Install via package manager (e.g., `apt install nmap`, `yum install nmap`, or download from [nmap.org](https://nmap.org/)).

2. **openssl**:

   - Used for manually testing specific ciphers and analyzing handshake messages.
   - Typically pre-installed on most Linux/Unix systems.

3. **testssl.sh**:

   - Used for comprehensive TLS testing.
   - Download the latest version from the [official GitHub repository](https://github.com/testssl/testssl.sh).

4. **Python 3**:
   - The tool requires Python 3.6 or later.
   - Install via package manager (e.g., `apt install python3`, `yum install python3`, or download from [python.org](https://www.python.org/)).

## Installation

1. Clone the repository:

   ```bash
   git clone https://github.com/<your-username>/tls-security-checker.git
   cd tls-security-checker
   ```

2. Install Python dependencies:

   ```bash
   pip install -r requirements.txt
   ```

3. Ensure `nmap`, `openssl`, and `testssl.sh` are installed and accessible in your `PATH`.

## Usage

The tool is modular, and each check is implemented as a separate class. You can run the tool using the command-line interface.

### Running the Script

```bash
$ python3 main.py --help
usage: main.py [-h] [-host HOST] [-port PORT] [-debug]

TLS Security Checker

options:
  -h, --help  show this help message and exit
  -host HOST  Target hostname
  -port PORT  Target port
  -debug      Enable Debug Logging
```

### Example:

```bash
$ python main.py -host example.com -port 8443
```

### Output

The tool logs the findings for each check. For example:

```
$ python3 main.py -host example.com -port 8443
2024-12-16 00:31:32,753 - INFO - ==== Starting TLS checks on example.com:8443 ====
2024-12-16 00:31:32,754 - INFO - Checking for supported TLS Versions and Ciphers...
2024-12-16 00:31:51,668 - INFO - Supported TLS versions: TLSv1.2, TLSv1.3
2024-12-16 00:31:51,669 - INFO - Checking for common prime...
2024-12-16 00:31:56,478 - WARNING - [!] Common Prime detected (TLSv1.2)
2024-12-16 00:31:59,509 - INFO - Checking for Weak MACs...
2024-12-16 00:31:59,511 - WARNING - [!!] Weak MACs detected (TLSv1.2)
2024-12-16 00:31:59,512 - INFO - Checking for usage of static key ciphers...
2024-12-16 00:31:59,514 - WARNING - [!] Static Key Ciphers detected (TLSv1.2)
2024-12-16 00:31:59,515 - INFO - Checking for usage of strong ciphers...
2024-12-16 00:31:59,517 - INFO - Found Usage of Strong Cipher. All Good!!!
2024-12-16 00:31:59,518 - INFO - Checking for common vulnerability...
2024-12-16 00:33:20,758 - WARNING - [!] Target vulnerable to LUCKY13 (CVE-2013-0169) - LOW
2024-12-16 00:33:20,760 - INFO - ==== TLS checks completed for example.com:8443 ====
```

### Available Checks

1. **TLS Versions Check**

   - Lists all supported TLS versions.

2. **Common Primes Check**

   - Detects if the server is using common DH primes.

3. **Weak MAC Algorithms Check**

   - Identifies weak MAC algorithms, such as MD5 and SHA1.

4. **Static Key Ciphers Check**

   - Flags the use of `TLS_RSA_WITH_*` ciphers.

5. **Strong Ciphers Check**

   - Detects the use of `DHE`, `ECDHE`, `AES-GCM`, and `ChaCha20-Poly1305` ciphers.

6. **testssl.sh Vulnerability Check**
   - Check for vulnerability using `testssl.sh -U`

## Logging

The tool uses Python's built-in logging module to log results. Logs are written to the console in a structured format for easy analysis.

## Project Structure

```
.
├── README.md
├── main.py
└── modules
    ├── common_prime.py
    ├── static_key.py
    ├── strong_cipher.py
    ├── tls_checker.py
    ├── tls_versions.py
    ├── vulnerabilities_check.py
    └── weak_macs.py
```

## Contributing

Contributions are welcome! If you'd like to add new checks or improve the tool, feel free to submit a pull request.

## License

This project is licensed under the Apache License 2.0. See the `LICENSE` file for details.

## Disclaimer

This tool is intended for educational and security testing purposes only. Ensure you have proper authorization before testing any servers.
