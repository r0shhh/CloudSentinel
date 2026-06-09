# CloudSentinel

A Python-based AWS misconfiguration scanner built to detect 
common cloud security issues.

## What It Does
Connects to AWS via boto3, runs security checks against 
your infrastructure, flagging misconfigurations that could expose your environment to risk and creates a report of findings with misconfigurations present and their severity levels

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
| Port 22/3389/3306/5432 open to 0.0.0.0/0 | EC2 | CRITICAL |
| CloudTrail not configured or not logging | CloudTrail | CRITICAL |
## Sample Output
```
Scanning 1 bucket(s)...

Bucket: cloudsentinel-test-bucket-rosh

Found 1 user(s):
- cloudsentinel-scanner
Scanning 1 security group(s)...

Security Group: sg-0ac922f6f7e2083a7 (default)

Scanning 1 CloudTrail trail(s)...

CloudTrail Trail: No trails found


==================================================
CLOUDSENTINEL SCAN REPORT
==================================================
Scan Time : 2026-06-09T16:23:43.488716
Total Findings: 1

Severity Breakdown:
 CRITICAL: 1
 HIGH: 0
 MEDIUM: 0
 LOW: 0

Findings:
--------------------------------------------------
[CRITICAL] check_cloudtrail
Resource : No trails found
! No CloudTrail trails configured - AWS activity is not being logged

==================================================

Report saved to reports/scan_report.json
```

## Project Status
Phase 4 complete. Core scanner functional across S3, IAM, EC2 and CloudTrail
