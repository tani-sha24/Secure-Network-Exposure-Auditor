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
- [ ] **Milestone 4:** Audit Reports (JSON/CSV)
- [ ] **Milestone 5:** Cryptography (Hashing, Digital Signatures, Encryption)
- [ ] **Milestone 6:** Testing and Final Portfolio Documentation

## Responsible Use
This tool is intended for authorized lab systems and systems for which the operator has permission to test. Scan results are observations of network reachability, not proof that a service is vulnerable.

## Planned Deliverables
- Python source code and automated tests
- Example security policies and audit reports
- Cryptographic integrity and signature verification
- Encrypted report handling
- Screenshots and setup documentation
