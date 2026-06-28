import boto3
from botocore.exceptions import ClientError


def check_ebs_encryption():
    ec2_client = boto3.client('ec2')

    try:
        response = ec2_client.describe_volumes()
        volumes = response['Volumes']
        results = []

        if not volumes:
            return []

        for volume in volumes:
            issues = []

            if not volume['Encrypted']:
                issues.append('EBS Volume is not encrypted')

            results.append({
                'volume_id': volume['VolumeId'],
                'status': 'FAIL' if issues else 'PASS',
                'issues': issues
            })

        return results

    except ClientError as e:
        error_code = e.response['Error']['Code']
        return [{
            'volume_id': 'unknown',
            'status': 'ERROR',
            'issues': [f'Unexpected error: {error_code}']
        }]