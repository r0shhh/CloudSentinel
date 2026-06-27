import importlib
from rich.progress import Progress, SpinnerColumn, TextColumn
from scanners.s3_scanner import list_buckets
from scanners.iam_scanner import list_iam_users
from reports.report_generator import ReportGenerator
from config.config_loader import load_checks_config
import logging
import argparse

logging.basicConfig(
    filename='logs/cloudsentinel.log',
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger('cloudsentinel')
logging.getLogger('botocore').setLevel(logging.WARNING)
logging.getLogger('boto3').setLevel(logging.WARNING)

def run_checks(report, checks_config, service_filter='all', severity_filter='all'):

    # Pre-fetch resources once
    buckets = None
    users = None

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        transient=True,
    ) as progress:
        
        scan_task = progress.add_task("[cyan]Initializing...", total=len(checks_config))

        for check_name, check in checks_config.items(): 

            #Skip disabled checks
            if not check.get('enabled', True):
                logger.info(f'Skipping disabled check: {check_name}')
                progress.advance(scan_task)
                continue

            #Skip if service filter doesn't match
            if service_filter != 'all' and check['service'] != service_filter:
                progress.advance(scan_task)
                continue
            
            if severity_filter != 'all' and check['severity'] != severity_filter:
                progress.advance(scan_task)
                continue

            # Dynamically load the scanner function
            module = importlib.import_module(check['module'])
            func = getattr(module, check['function'])
            severity = check['severity']
            resource_type = check['resource_type']

            # Execute based on resource type
            if resource_type == 's3_bucket':
                if buckets is None:
                    progress.update(scan_task, description="[yellow]Fetching S3 Buckets from AWS...")
                    buckets = list_buckets()
                    
                for bucket in buckets:
                    name = bucket['Name']
                    progress.update(scan_task, description=f"[cyan]Scanning S3 Bucket: {name}")
                    result = func(name)
                    report.add_finding(check_name, result, severity, check.get('cis_control', 'N/A'))

            elif resource_type == 'iam_user':
                if users is None:
                    progress.update(scan_task, description="[yellow]Fetching IAM Users from AWS...")
                    users = list_iam_users()
                    
                for user in users:
                    progress.update(scan_task, description=f"[cyan]Scanning IAM User: {user['UserName']}")
                    result = func(user['UserName'])
                    report.add_finding(check_name, result, severity, check.get('cis_control', 'N/A'))
                
            elif resource_type == 'none':
                metadata_keys = ['module', 'function', 'resource_type', 'service', 'severity', 'cis_control', 'enabled', 'description', 'remediation']
                extra_params = {k: v for k, v in check.items() if k not in metadata_keys}
                progress.update(scan_task, description=f"[cyan]Running account check: {check_name}")

                results = func(**extra_params)
                if isinstance(results, list):
                    for result in results:
                        report.add_finding(check_name, result, severity, check.get('cis_control', 'N/A'))
                else:
                    report.add_finding(check_name, results, severity, check.get('cis_control', 'N/A'))
            
            progress.advance(scan_task)

if __name__ == "__main__":

    parser = argparse.ArgumentParser(
        description='CloudSentinel - AWS Misconfiguration Scanner'
    )
    parser.add_argument(
        '--service',
        choices=['s3', 'iam', 'ec2', 'cloudtrail', 'rds', 'all'],
        default='all',
        help='Service to scan (default: all)'
    )
    parser.add_argument(
        '--severity',
        choices=['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'all'],
        default='all',
        help='Only run checks of this severity level'
    )
    args = parser.parse_args()

    checks_config = load_checks_config()
    report = ReportGenerator()

    logger.info(f'Scan started - service: {args.service}')
    run_checks(report, checks_config, args.service, args.severity)

    report.print_report()
    report.save_json_report('reports/scan_report.json')
    logger.info('Report saved')