import boto3
from moto import mock_aws
from unittest.mock import patch
from datetime import datetime, timedelta, timezone
from scanners.iam_scanner import check_user_mfa, check_access_key_age, check_admin_privileges


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