from scanners.s3_scanner import list_buckets, check_public_access_block, check_bucket_encryption
from scanners.iam_scanner import list_iam_users, check_user_mfa, check_access_key_age, check_admin_privileges
from scanners.ec2_scanner import check_security_groups
from scanners.cloudtrail_scanner import check_cloudtrail
from reports.report_generator import ReportGenerator
from config.config_loader import load_checks_config
import logging

logging.basicConfig(
    filename='logs/cloudsentinel.log',
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

logger = logging.getLogger('cloudsentinel')
logging.getLogger('botocore').setLevel(logging.WARNING)
logging.getLogger('boto3').setLevel(logging.WARNING)

def run_s3_checks(report, checks_config):
    buckets = list_buckets()

    if not buckets:
        print("No S3 buckets found.")
        return
    print(f"Scanning {len(buckets)} bucket(s)...\n")

    for bucket in buckets:
        name = bucket['Name']
        print(f"Bucket: {name}")

        if checks_config.get('s3_block_public_access', {}).get('enabled', True):
            result = check_public_access_block(name)
            report.add_finding('check_public_access_block',
            result,
            checks_config.get('s3_block_public_access', {}).get('severity', 'UNKNOWN')
            )

        if checks_config.get('s3_bucket_encryption', {}).get('enabled', True):
            result = check_bucket_encryption(name)
            report.add_finding('check_bucket_encryption', 
            result,
            checks_config.get('s3_bucket_encryption', {}).get('severity', 'UNKNOWN')
            )

            print() 

    logger.info('S3 checks complete')

def run_iam_checks(report, checks_config): 
    users = list_iam_users()

    if not users:
        print("No IAM users found.")
    else:
        print(f"Found {len(users)} user(s):")
        for user in users:
            print (f"- {user['UserName']}")
            
            if checks_config.get('iam_user_mfa', {}).get('enabled', True):
                result = check_user_mfa(user['UserName'])
                report.add_finding('check_user_mfa',
                result,
                checks_config.get('iam_user_mfa', {}).get('severity', 'UNKNOWN')
                )

            if checks_config.get('iam_access_key_age', {}).get('enabled', True):
                result = check_access_key_age(user['UserName'])
                report.add_finding('check_access_key_age',
                result,
                checks_config.get('iam_access_key_age', {}).get('severity', 'UNKNOWN')
                )

            if checks_config.get('iam_admin_privileges', {}).get('enabled', True):
                result = check_admin_privileges(user['UserName'])
                report.add_finding('check_admin_privileges',
                result,
                checks_config.get('iam_admin_privileges', {}).get('severity', 'UNKNOWN')
                )  

    logger.info('IAM checks complete')

def run_ec2_checks(report, checks_config):

    if checks_config.get('ec2_security_group_ports', {}).get('enabled', True):
        results = check_security_groups()
        print(f"Scanning {len(results)} security group(s)...\n")
        for result in results:
            print(f"Security Group: {result['group_id']} ({result['group_name']})")
            report.add_finding('check_security_groups',
            result,
            checks_config.get('ec2_security_group_ports', {}).get('severity', 'UNKNOWN')
            )

        print()
    logger.info('EC2 checks complete')
     
def run_cloudtrail_checks(report, checks_config):

    if checks_config.get('cloudtrail_logging', {}).get('enabled', True):
        results = check_cloudtrail()
        print(f"Scanning {len(results)} CloudTrail trail(s)...\n")
        for result in results:
            print(f"CloudTrail Trail: {result['trail_name']}")
            report.add_finding('check_cloudtrail',
            result,
            checks_config.get('cloudtrail_logging', {}).get('severity', 'UNKNOWN')
            )

        print()
    logger.info('CloudTrail checks complete')     

if __name__ == "__main__":

    checks_config = load_checks_config()
    
    import argparse
    
    parser = argparse.ArgumentParser(description='CloudSentinel - AWS Misconfiguration Scanner')
    parser.add_argument('--service', choices=['s3', 'iam', 'ec2', 'cloudtrail', 'all'], default='all', help='Service to scan')
    args = parser.parse_args()
    logger.info(f'Scan started - service: {args.service}')
    report = ReportGenerator()

    if args.service == 's3' or args.service == 'all':
        run_s3_checks(report, checks_config)

    if args.service == 'iam' or args.service == 'all':                           
        run_iam_checks(report, checks_config)

    if args.service == 'ec2' or args.service == 'all':
        run_ec2_checks(report, checks_config)

    if args.service == 'cloudtrail' or args.service == 'all':
        run_cloudtrail_checks(report, checks_config)
        
    report.print_report()
    report.save_json_report('reports/scan_report.json')
    logger.info('Report saved')

  