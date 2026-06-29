import boto3
from botocore.exceptions import ClientError

def check_rds_public_access():
    """
    Checks if any RDS instance is publicly accessible
    Returns a finding
    """
    rds_client = boto3.client('rds')

    try:
        response = rds_client.describe_db_instances()
        db_instances = response['DBInstances']
        issues = []
        results = []
        
        if not db_instances: 
            return []

        for instance in db_instances:
            issues = []
            if instance['PubliclyAccessible']:
                issues.append('Database is Publicly Accessible')

            results.append ({
                'resource_id' : instance['DBInstanceIdentifier'],
                'status' : 'FAIL' if issues else 'PASS',
                'issues' : issues
            }) 

        return results
    except ClientError as e:
        error_code = e.response['Error']['Code']
        return [{'resource_id': 'unknown', 'status': 'ERROR', 'issues': [f'Unexpected error: {error_code}']}]
