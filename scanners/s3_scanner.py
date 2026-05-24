import boto3
from botocore.exceptions import ClientError

def list_buckets():
    """
    Connect to AWS and return all s3 buckets in the account.
    """
    s3_client = boto3.client('s3')

    response = s3_client.list_buckets()

    return response['Buckets']

def check_public_access_block(bucket_name):
    """
    Check if Block Public Access is properly enabled on a bucket.
    Returns a finding if any setting is disabled.
    """
    s3_client = boto3.client('s3')

    try:
        response = s3_client.get_public_access_block(
            Bucket=bucket_name
            )
        config = response['PublicAccessBlockConfiguration']

        issues = []

        if not config.get('BlockPublicAcls'):
            issues.append('BlockPublicAcls is disabled')

        if not config.get('IgnorePublicAcls'):
            issues.append('IgnorePublicAcls is disabled')

        if not config.get('BlockPublicPolicy'):
            issues.append('BlockPublicPolicy is disabled')

        if not config.get('RestrictPublicBuckets'):
            issues.append('RestrictPublicBuckets is disabled')

        if issues:
            return {
                'bucket': bucket_name,
                'status': 'FAIL',
                'issues': issues
            }                
        else:
            return {
                'bucket': bucket_name,
                'status': 'PASS',
                'issues' : []
            }
    except ClientError as e:
        error_code = e.response['Error']['Code']

        if error_code == 'NoSuckPublicAccessBlockConfiguration':
            return {
                'bucket': bucket_name,
                'status': 'FAIL',
                'issues': ['No Block Public Access configuration found']
            }
        else:
            return {
                'bucket': bucket_name,
                'status': 'Error',
                'issues': [f'Unexpected error: {error_code}']
            }
        
def check_bucket_encryption(bucket_name):
    """
    Check if bucket encryption is enabled.
    Returns a finding if encryption is not configured.
    """
    s3_client = boto3.client('s3')

    try:
        response = s3_client.get_bucket_encryption(Bucket=bucket_name)
        return {
            'bucket': bucket_name,
            'status': 'PASS',
            'issues': []
        }

    except ClientError as e:
        error_code = e.response['Error']['Code']

        if error_code == 'ServerSideEncryptionConfigurationNotFoundError':
            return {
                'bucket': bucket_name,
                'status': 'FAIL',
                'issues': ['Bucket encryption is not configured']
            }
        else:
            return {
                'bucket': bucket_name,
                'status': 'ERROR',
                'issues': [f'Unexpected error: {error_code}']
            }
