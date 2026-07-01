import boto3
from botocore.exceptions import ClientError
from datetime import datetime, timezone


def list_iam_users():
    """
    Connect to AWS and list all IAM users in the account.
    """
    iam_client = boto3.client('iam')

    response = iam_client.list_users()

    return response['Users']

def check_user_mfa(username):
    """
    Check if MFA is enabled for a given IAM user
    Returns a finding if MFA is not enabled.
    """
    iam_client = boto3.client('iam')

    try:
        iam_client.get_login_profile(UserName=username)
    except ClientError as e:
        if e.response['Error']['Code'] == 'NoSuchEntity':
            return {
                'resource_id': username,
                'status': 'PASS',
                'issues': [],
            }
        else:
            return {
                'resource_id': username,
                'status': 'ERROR',
                'issues': [f'Unexpected error checking login profile']
            }
    
    try:
        response = iam_client.list_mfa_devices(UserName=username)
        mfa_devices = response['MFADevices']

        if not mfa_devices:
            return{
                'resource_id': username,
                'status': 'FAIL',
                'issues': ['MFA is not enabled for this user']
            }
        else:
            return {
                'resource_id': username,
                'status': 'PASS',
                'issues': []        

            }

    except ClientError as e:
        error_code = e.response['Error']['Code']
        return {
            'resource_id': username,
            'status': 'ERROR',
            'issues': [f'Unexpected error: {error_code}']
        }
    
def check_access_key_age(username):
    """
    check the age of access keys for a given IAM user
    returns a finding if any access key is older than 90 days
    """
    iam_client = boto3.client('iam')
    try:
        response = iam_client.list_access_keys(UserName=username)
        access_keys = response['AccessKeyMetadata']
        issues = []

        for key in access_keys:
            if key['Status'] != 'Active':
                continue #skip inactive keys

            age = datetime.now(timezone.utc) - key['CreateDate']
            age_in_days = age.days

            if age_in_days > 90:
                issues.append(f"Access key {key['AccessKeyId']} is {age_in_days} days old")

        if issues: 
            return {
                'resource_id' : username,
                'status' : 'FAIL',
                'issues' : issues
            }        
        else: 
            return {
                'resource_id' : username,
                'status' : 'PASS',
                'issues' : []
            }
    except ClientError as e:
        error_code = e.response['Error']['Code']
        return {
            'resource_id' : username,
            'status' : 'ERROR',
            'issues' : [f'Unexpected error: {error_code}']
        }
    
def check_admin_privileges(username):
    """
    Check if the given IAM user has administrative privileges
    returns a finding if the user has admin access
    """
    iam_client = boto3.client('iam')
    try:
        response = iam_client.list_attached_user_policies(UserName=username)
        policies = response['AttachedPolicies']
        issues = []

        for policy in policies:
            if policy['PolicyArn'] == 'arn:aws:iam::aws:policy/AdministratorAccess':
                issues.append('User has Admin Privileges')
        if issues: 
            return {
                'resource_id' : username,
                'status' : 'FAIL',
                'issues' : issues
            }
        else:
            return {
                'resource_id' : username,
                'status' : 'PASS',
                'issues' : []
            }
    except ClientError as e:
        error_code = e.response['Error']['Code']
        return {
            'resource_id' : username,
            'status' : 'ERROR',
            'issues' : [f"Unexpected error: {error_code}"]

        }            

def check_root_access_key():
    """
    Check whether the AWS account root user has an active access key.
    """
    iam_client = boto3.client('iam')

    iam_client.generate_credential_report()
    response = iam_client.get_credential_report()

    content = response['Content'].decode('utf-8')

    lines = content.splitlines()
    for line in lines:
        if line.startswith("<root_account>"):
            fields = line.split(',')
            access_key_1 = fields[8]
            access_key_2 = fields[13]

            if access_key_1 == "true" or access_key_2 == "true":
               return {
                   "resource_id": "<root_account>",
                   "status": "FAIL",
                   "issues": ["Root user has an active access key"]
             }
            else:
              return {
                  "resource_id": "<root_account>",
                  "status": "PASS",
                  "issues": []
                  }
