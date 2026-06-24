# CloudSentinel

A Python-based AWS misconfiguration scanner built to detect 
common cloud security issues.

## What It Does
Connects to AWS via boto3, runs security checks against 
your infrastructure, flagging misconfigurations that could expose your environment to risk and creates a report of findings with misconfigurations present and their severity levels

## Architecture

CloudSentinel uses a config-driven plugin architecture. All checks 
are defined in `config/checks.yaml` with their module, function, 
severity, and parameters. The scanner dynamically loads and executes 
checks using Python's `importlib` — adding a new check requires only 
writing the scanner function and adding one YAML entry. No changes 
to `main.py` are needed.

Supports filtering by service (`--service`) and severity (`--severity`).

## Tech Stack
- Python 3
- boto3 (AWS SDK for Python)
- AWS Free Tier

## Prerequisites
- AWS account
- IAM user
- Python 3.8+
- AWS CLI

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

| Check | Service | Severity |
|---|---|---|
| Block Public Access disabled | S3 | CRITICAL |
| Bucket encryption not configured | S3 | MEDIUM |
| MFA not enabled for console users | IAM | HIGH |
| Access key older than 90 days | IAM | MEDIUM |
| User has admin privileges | IAM | CRITICAL |
| Port 22/3389/3306/5432 open to 0.0.0.0/0 | EC2 | CRITICAL |
| CloudTrail not configured or not logging | CloudTrail | CRITICAL|
| Database publicly accessible | RDS | CRITICAL
## Sample Output
```
Scanning 1 bucket(s)... 

[s3_block_public_access] cloudsentinel-test-bucket-rosh
[s3_bucket_encryption] cloudsentinel-test-bucket-rosh
Found 1 user(s)...

==================================================
CLOUDSENTINEL SCAN REPORT
==================================================
Scan Time : 2026-06-23T01:00:52.980199
Total Findings: 1

Severity Breakdown:
 CRITICAL: 1
 HIGH: 0
 MEDIUM: 0
 LOW: 0

Findings:
--------------------------------------------------
[CRITICAL] cloudtrail_logging
Resource : No trails found
! No CloudTrail trails configured - AWS activity is not being logged

==================================================

Report saved to reports/scan_report.json
```

## Project Status
Core scanner functional across S3, IAM, EC2, CloudTrail, and RDS.\
Refactored into a config-driven plugin architecture for easy extensibility.
