import boto3
from moto import mock_aws
from unittest.mock import patch
from datetime import datetime, timedelta, timezone
from scanners.iam_scanner import (
    check_user_mfa,
    check_access_key_age,
    check_admin_privileges,
    check_root_access_key,
)

@mock_aws
def test_check_user_mfa_no_console_access():
    iam_client = boto3.client('iam', region_name='us-east-1')
    iam_client.create_user(UserName='test-user')

    result = check_user_mfa('test-user')

    assert result['status'] == 'PASS'


@mock_aws
def test_check_user_mfa_console_access_without_mfa():
    iam_client = boto3.client('iam', region_name='us-east-1')
    iam_client.create_user(UserName='test-user')

    iam_client.create_login_profile(
        UserName='test-user',
        Password='TestPassword123!'
    )

    result = check_user_mfa('test-user')

    assert result['status'] == 'FAIL'


@mock_aws
def test_check_user_mfa_console_access_with_mfa():
    iam_client = boto3.client('iam', region_name='us-east-1')
    iam_client.create_user(UserName='test-user')

    iam_client.create_login_profile(
        UserName='test-user',
        Password='TestPassword123!'
    )

    iam_client.enable_mfa_device(
        UserName='test-user',
        SerialNumber='arn:aws:iam::123456789012:mfa/test-user',
        AuthenticationCode1='123456',
        AuthenticationCode2='654321'
    )

    result = check_user_mfa('test-user')

    assert result['status'] == 'PASS'

@mock_aws
def test_check_access_key_age_no_keys():
    iam_client = boto3.client('iam', region_name='us-east-1')
    iam_client.create_user(UserName='test-user')

    result = check_access_key_age('test-user')

    assert result['status'] == 'PASS'


@mock_aws
def test_check_access_key_age_recent():
    iam_client = boto3.client('iam', region_name='us-east-1')
    iam_client.create_user(UserName='test-user')
    iam_client.create_access_key(UserName='test-user')

    result = check_access_key_age('test-user')

    assert result['status'] == 'PASS'


def test_check_access_key_age_fail():
    old_date = datetime.now(timezone.utc) - timedelta(days=100)

    fake_response = {
        'AccessKeyMetadata': [
            {
                'AccessKeyId': 'FAKEKEY123',
                'Status': 'Active',
                'CreateDate': old_date
            }
        ]
    }

    with patch('boto3.client') as mock_client:
        mock_client.return_value.list_access_keys.return_value = fake_response
        result = check_access_key_age('test-user')

    assert result['status'] == 'FAIL'



@mock_aws
def test_check_admin_privileges_no_policy():
    iam_client = boto3.client('iam', region_name='us-east-1')
    iam_client.create_user(UserName='test-user')
 

    result = check_admin_privileges('test-user')

    assert result['status'] == 'PASS'


@mock_aws(config={"iam": {"load_aws_managed_policies": True}})
def test_check_admin_privileges_non_admin_policy():
    iam_client = boto3.client('iam', region_name='us-east-1')
    iam_client.create_user(UserName='test-user')
    iam_client.attach_user_policy(
        UserName='test-user',
        PolicyArn='arn:aws:iam::aws:policy/ReadOnlyAccess'
    )

    result = check_admin_privileges('test-user')

    assert result['status'] == 'PASS'


@mock_aws(config={"iam": {"load_aws_managed_policies": True}})
def test_check_admin_privileges_admin_policy():
    iam_client = boto3.client('iam', region_name='us-east-1')
    iam_client.create_user(UserName='test-user')
    iam_client.attach_user_policy(
        UserName='test-user',
        PolicyArn='arn:aws:iam::aws:policy/AdministratorAccess'
    )

    result = check_admin_privileges('test-user')

    assert result['status'] == 'FAIL'
    
    
    
def test_check_root_access_key_pass():
    fake_report = (
        "user,arn,user_creation_time,password_enabled,password_last_used,password_last_changed,"
        "password_next_rotation,mfa_active,access_key_1_active,access_key_1_last_rotated,"
        "access_key_1_last_used_date,access_key_1_last_used_region,access_key_1_last_used_service,"
        "access_key_2_active,access_key_2_last_rotated,access_key_2_last_used_date,"
        "access_key_2_last_used_region,access_key_2_last_used_service,cert_1_active,"
        "cert_1_last_rotated,cert_2_active,cert_2_last_rotated\n"
        "<root_account>,arn:aws:iam::123456789012:root,,,,,,true,false,,,,,false,,,,,false,,false,"
    )

    with patch("boto3.client") as mock_client:
        mock_client.return_value.generate_credential_report.return_value = {}

        mock_client.return_value.get_credential_report.return_value = {
            "Content": fake_report.encode("utf-8")
        }

        result = check_root_access_key()

    assert result["status"] == "PASS"