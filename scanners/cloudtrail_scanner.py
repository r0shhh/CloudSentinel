import boto3
from botocore.exceptions import ClientError

def check_cloudtrail():
    cloudtrail_client = boto3.client('cloudtrail')

    try:
        response = cloudtrail_client.describe_trails()
        trails = response['trailList']
        results = []   

        if not trails:
            return [{
            'resource_id': 'No trails found',
            'status': 'FAIL',
            'issues': ['No CloudTrail trails configured - AWS activity is not being logged']
        }]     

        for trail in trails:
            issues = []
            status = cloudtrail_client.get_trail_status(Name=trail['TrailARN'])
            is_logging = status['IsLogging']
            if not is_logging:
                issues.append("CloudTrail is not logging")

            if not trail['IsMultiRegionTrail']:
                issues.append("CloudTrail is not multi-region")

            results.append({
                'resource_id': trail['Name'],
                'status': 'FAIL' if issues else 'PASS',
                'issues': issues
             })

        return results
    except ClientError as e:
        error_code = e.response['Error']['Code']
        return [{'resource_id': 'unknown', 'status': 'ERROR', 'issues': [f'Unexpected error: {error_code}']}]    