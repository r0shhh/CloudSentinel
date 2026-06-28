import boto3
from botocore.exceptions import ClientError


def check_security_groups(dangerous_ports=None):
    if dangerous_ports is None:
        dangerous_ports = [22, 3389, 3306, 5432]

    ec2_client = boto3.client('ec2')

    try:
        response = ec2_client.describe_security_groups()
        security_groups = response['SecurityGroups']
        results = []

        for sg in security_groups:
            issues=[]
            for rule in sg['IpPermissions']:
                port = rule.get('FromPort')
                if port in dangerous_ports:
                    for ip_range in rule.get('IpRanges', []):
                        if ip_range['CidrIp'] == '0.0.0.0/0':
                            issues.append(f"Port {port} open to 0.0.0.0/0 (IPv4)")
                    for ip_range in rule.get('Ipv6Ranges', []):
                        if ip_range['CidrIpv6'] == '::/0':
                            issues.append(f"Port {port} open to ::/0 (IPv6)")

            results.append({
                'resource_id': sg['GroupId'],
                'group_name': sg['GroupName'],
                'status': 'FAIL' if issues else 'PASS',
                'issues': issues
             })

        return results
    
    except ClientError as e:
        error_code = e.response['Error']['Code']
        return [{'resource_id': 'unknown', 'group_name': 'unknown', 'status': 'ERROR', 'issues': [f'Unexpected error: {error_code}']}]
    