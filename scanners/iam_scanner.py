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
                'user': username,
                'status': 'PASS',
                'issues': [],
            }
        else:
            return {
                'user': username,
                'status': 'ERROR',
                'issues': [f'Unexpected error checking login profile']
            }
    
    try:
        response = iam_client.list_mfa_devices(UserName=username)
        mfa_devices = response['MFADevices']

        if not mfa_devices:
            return{
                'user': username,
                'status': 'FAIL',
                'issues': ['MFA is not enabled for this user']
            }
        else:
            return {
                'user': username,
                'status': 'PASS',
                'issues': []        

            }

    except ClientError as e:
        error_code = e.response['Error']['Code']
        return {
            'user': username,
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
                'user' : username,
                'status' : 'FAIL',
                'issues' : issues
            }        
        else: 
            return {
                'user' : username,
                'status' : 'PASS',
                'issues' : []
            }
    except ClientError as e:
        error_code = e.response['Error']['Code']
        return {
            'user' : username,
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
                'user' : username,
                'status' : 'FAIL',
                'issues' : issues
            }
        else:
            return {
                'user' : username,
                'status' : 'PASS',
                'issues' : []
            }
    except ClientError as e:
        error_code = e.response['Error']['Code']
        return {
            'user' : username,
            'status' : 'ERROR',
            'issues' : [f"Unexpected error: {error_code}"]

        }            

