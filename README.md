# CloudSentinel

A Python-based AWS misconfiguration scanner built to detect 
common cloud security issues.

## What It Does
Connects to AWS via boto3, runs security checks against 
your infrastructure, flagging misconfigurations that could expose your environment to risk and creates a report of findings with misconfigurations present and there severity levels

## Tech Stack
- Python 3
- boto3 (AWS SDK for Python)
- AWS Free Tier

## Prerequisites
- AWS account
- IAM user
- Python 3.8+
- AWS CLI


## Setup
```bash
git clone https://github.com/r0shhh/CloudSentinel
cd CloudSentinel
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
aws configure
python3 main.py
```

## Current Checks

| Check | Service | Severity |
|---|---|---|
| Block Public Access disabled | S3 | CRITICAL |
| Bucket encryption not configured | S3 | MEDIUM |
| MFA not enabled for console users | IAM | HIGH |
| Access key older than 90 days | IAM | MEDIUM |
| User has admin privileges | IAM | CRITICAL |
## Sample Output
```
Scanning 1 bucket(s)...

Bucket: cloudsentinel-test-bucket-rosh

Found 1 user(s):
- cloudsentinel-scanner

==================================================
CLOUDSENTINEL SCAN REPORT
==================================================
Scan Time : 2026-05-28T18:24:26.648581
Total Findings: 0

Severity Breakdown:
 CRITICAL: 0
 HIGH: 0
 MEDIUM: 0
 LOW: 0
 No findings. All checks passed.
==================================================

Report saved to reports/scan_report.json
```

## Project Status
Phase 3 complete - reporting system with severity levels implemented, Adding more checks in Phase 4