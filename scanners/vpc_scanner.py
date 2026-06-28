import boto3
from botocore.exceptions import ClientError

def check_vpc_flow_logs():
    """
    Checks if VPC Flow Logs are Enabled for all VPCs
    Returns a finding
    """
    ec2_client = boto3.client('ec2')

    try:
        vpcs = ec2_client.describe_vpcs()['Vpcs']
        issues = []
        results = []

        if not vpcs:
            return []
        
        for vpc in vpcs:
            vpc_id = vpc['VpcId']
            issues = []
            flow_logs = ec2_client.describe_flow_logs(Filters=[{
                'Name': 'resource-id',
                'Values': [vpc_id]}])['FlowLogs']
            if not flow_logs:
                issues.append('VPC Flow Logs are not enabled for this VPC')
            
            results.append({
                'vpc_id' : vpc_id,
                'status' : 'FAIL' if issues else 'PASS',
                'issues' : issues
            })

        return results
    except ClientError as e:
        error_code = e.response['Error']['Code']
        return [{'vpc_id': 'unknown', 'status': 'ERROR', 'issues': [f'Unexpected error: {error_code}']}]
