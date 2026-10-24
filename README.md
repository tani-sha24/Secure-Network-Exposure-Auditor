# Secure Network Exposure Auditor
A Python-based network security project that identifies reachable TCP services on authorized lab systems, compares observed exposure against a defined security policy, and generates audit reports.

## Objectives
- Build a lightweight TCP port-checking tool in Python.
- Validate IP addresses and restrict scans to explicitly authorized targets.
- Compare observed ports with expected service policies.
- Export findings to JSON and CSV.
- Use SHA-256 to check report integrity.
- Add digital signatures and authenticated encryption using established cryptographic libraries.
- Test the tool and document its limitations.

## Technologies
- Python 3
- Linux and TCP/IP networking
- Python socket and ipaddress libraries
- Wireshark
- Python cryptography library
- GitHub

## Project Status
- [x] **Milestone 1:** Repository and Environment Setup
- [x] **Milestone 2:** TCP Port Scanner
- [x] **Milestone 3:** Security Policy Auditing
- [x] **Milestone 4:** Audit Reports (JSON/CSV)
- [x] **Milestone 5:** Cryptography (Hashing, Digital Signatures, Encryption)
- [x] **Milestone 6:** Testing and Final Portfolio Documentation

## Responsible Use
This tool is intended for authorized lab systems and systems for which the operator has permission to test. Scan results are observations of network reachability, not proof that a service is vulnerable.

## Planned Deliverables
- Python source code and automated tests
- Example security policies and audit reports
- Cryptographic integrity and signature verification
- Encrypted report handling
- Screenshots and setup documentation

## Installation

### Requirements
- Python 3.10 or newer
- `pip`
- The `cryptography` Python package

### Setup on Linux
Clone the repository and enter the project directory:

```bash
git clone https://github.com/YOUR-USERNAME/Secure-Network-Exposure-Auditor.git
cd Secure-Network-Exposure-Auditor
```

Create and activate a virtual environment:

```bash
python3 -m venv .venv
source .venv/bin/activate
```

Install the required dependency:

```bash
python -m pip install cryptography
```

## Usage

### Run the TCP exposure checker
```bash
python src/minimap.py
```

### Run the security policy audit
```bash
python src/audit.py
```

The audit checks configured TCP ports against the expected-services policy and generates JSON and CSV reports in the `reports/` directory.

### Verify report integrity
Generate a SHA-256 checksum:

```bash
python src/integrity.py hash reports/REPORT.json
```

Verify the report later:

```bash
python src/integrity.py verify reports/REPORT.json
```

Replace `REPORT.json` with the actual report filename.

### Run the test suite

```bash
python -m unittest discover -s tests -v
```

## Cryptography Features
- **SHA-256:** Detects changes to files by comparing their digests.
- **Ed25519 digital signatures:** Verifies that a signed file matches the signature and public key.
- **Fernet authenticated encryption:** Protects report confidentiality and detects tampering.

Private signing and encryption keys must be kept secret and must never be committed to the repository.

## Security and Ethical Use
- Scan only systems you own or have explicit permission to assess.
- The scanner is restricted to loopback and private IPv4 targets.
- An open port does not automatically indicate a vulnerability.
- A policy alert means the observed result differs from the configured expectation; investigate before drawing conclusions.
- SHA-256 checksums alone do not prove who created a file.
- Digital signature verification depends on trusting the public key used for verification.
- Encryption keys must be protected and backed up securely.

## Project Limitations
This project performs a limited TCP port check. It is not a full vulnerability scanner, does not establish that a service is exploitable, and does not replace a professional security assessment.
