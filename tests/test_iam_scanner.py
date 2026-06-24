import boto3
from moto import mock_aws
from scanners.iam_scanner import check_user_mfa

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