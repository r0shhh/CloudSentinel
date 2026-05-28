from scanners.s3_scanner import list_buckets, check_public_access_block, check_bucket_encryption
from scanners.iam_scanner import list_iam_users, check_user_mfa, check_access_key_age, check_admin_privileges
from reports.report_generator import ReportGenerator

def run_s3_checks(report):
    buckets = list_buckets()

    if not buckets:
        print("No S3 buckets found.")
        return
    print(f"Scanning {len(buckets)} bucket(s)...\n")

    for bucket in buckets:
        name = bucket['Name']
        print(f"Bucket: {name}")

        result = check_public_access_block(name)
        report.add_finding('check_public_access_block', result)

        result = check_bucket_encryption(name)
        report.add_finding('check_bucket_encryption', result)

        print() 


def run_iam_checks(report): 
    users = list_iam_users()

    if not users:
        print("No IAM users found.")
    else:
        print(f"Found {len(users)} user(s):")
        for user in users:
            print (f"- {user['UserName']}")
            
            result = check_user_mfa(user['UserName'])
            report.add_finding('check_user_mfa', result)

            result = check_access_key_age(user['UserName'])
            report.add_finding('check_access_key_age', result)

            result = check_admin_privileges(user['UserName'])
            report.add_finding('check_admin_privileges', result)       

if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description='CloudSentinel - AWS Misconfiguration Scanner')
    parser.add_argument('--service', choices=['s3', 'iam', 'all'], default='all', help='Service to scan')
    args = parser.parse_args()

    report = ReportGenerator()

    if args.service == 's3' or args.service == 'all':
        run_s3_checks(report)

    if args.service == 'iam' or args.service == 'all':                           
        run_iam_checks(report)

    report.print_report()
    report.save_json_report('reports/scan_report.json')

  