# CloudSentinel

A high-performance, modular AWS security auditing tool designed to detect misconfigurations in real-time.

## Why CloudSentinel?
In modern cloud environments, infrastructure grows faster than security policies. CloudSentinel solves the "audit gap" - the time between an infrastructure misconfiguration (like an open S3 bucket) and detection. It provides a lightweight, config-driven approach that allows security teams to deploy custom checks in minutes without modifying the core engine.

## Engineering Highlights
- **Config-Driven Architecture:** Leveraged `importlib` for dynamic plugin loading, enabling a "write-once, scan-anywhere" workflow for new security checks.
- **Granular CLI Control:** Implemented flexible filtering via CLI flags (`--service`, `--severity`), allowing users to perform targeted audits and reduce noise in large environments.
- **Robust Mock-Testing:** Implemented comprehensive unit testing using `pytest` and `moto` to simulate complex AWS environments without risking live production data.
- **Next-Gen CLI Experience:** Refactored the reporting layer using the `Rich` library to provide real-time progress tracking and a clean, color-coded executive summary.
- **Compliance-First Design:** Integrated industry-standard CIS benchmark mapping directly into the reporting engine, providing immediate context and actionable remediation guidance for all findings.

## Architecture

CloudSentinel follows a modular, decoupled architecture:
* **Orchestration Layer:** `main.py` coordinates the scan, filters resources, and manages task flow.
* **Scanner Layer:** Independent modules in `scanners/` interact with AWS via `boto3`.
* **Configuration Engine:** Uses `checks.yaml` to define scan parameters, mapping specific security checks to their modules, severity levels, and CIS benchmarks.
* **Reporting Layer:** The `ReportGenerator` processes findings and renders them into the CLI dashboard using `Rich`.

## Sample Output
![alt text](image.png)

## Tech Stack
- Python 3
- boto3 (AWS SDK for Python)
- AWS Free Tier

## Prerequisites
- **Core:** Python 3 
- **Cloud SDK:** `boto3`
- **Testing:** `pytest`, `moto`
- **UI/UX:** `rich`

#### IAM policies needed:
- AmazonS3ReadOnlyAccess
- IAMReadOnlyAccess
- AmazonEC2ReadOnlyAccess
- AWSCloudTrail_ReadOnlyAccess
- AmazonRDSReadOnlyAccess


## Setup
```bash
git clone https://github.com/r0shhh/CloudSentinel
cd CloudSentinel
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
aws configure
python3 main.py                      # run all checks
python3 main.py --service s3         # only S3 checks
python3 main.py --severity CRITICAL  # only CRITICAL findings
```

## Current Checks

| Check | Service | Severity | CIS |
|---|---|---|---|
| Block Public Access disabled | S3 | HIGH | 2.1.4 |
| MFA not enabled for console users | IAM | MEDIUM | 1.9 |  
| Access key older than 90 days | IAM | MEDIUM | 1.13 |
| User has admin privileges | IAM | HIGH | 1.15 |
| Port 22/3389/3306/5432 open to 0.0.0.0/0 | EC2 | HIGH | 5.3 & 5.4 |
| CloudTrail not configured or not logging | CloudTrail | HIGH | 3.1 |
| Database publicly accessible | RDS | CRITICAL | 2.2.3 |

## Project Status
- [x] **Core Engine:** Fully functional modular scanner supporting S3, IAM, EC2, CloudTrail, and RDS.
- [x] **Extensibility:** Successfully implemented a decoupled, config-driven architecture.
- [x] **Reporting:** Automated JSON exports and a polished, real-time interactive terminal UI.
- [x] **Testing:** High-coverage unit testing implemented to ensure security check reliability.
- [x] **Compliance:** Baseline mapping to CIS AWS Foundations benchmarks active.

## Future Roadmap
- [ ] **Expanded Scanner Coverage:** Integrate checks for additional AWS services like Lambda, RDS encryption, and advanced IAM policy analysis.
- [ ] **Multi-Region Support:** Enable concurrent scans across multiple AWS regions to provide a comprehensive, global security posture view.
- [ ] **Enhanced Reporting:** Implement PDF and HTML export formats to facilitate easier sharing of audit results with non-technical stakeholders.