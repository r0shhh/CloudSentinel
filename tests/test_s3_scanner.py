import boto3
from moto import mock_aws
from scanners.s3_scanner import check_public_access_block


@mock_aws
def test_check_public_access_block_fail():

    s3_client = boto3.client('s3', region_name='us-east-1')
    s3_client.create_bucket(Bucket='test-bucket')

    result = check_public_access_block('test-bucket')

    assert result['status'] == 'FAIL'

@mock_aws
def test_check_public_access_block_pass():

    s3_client = boto3.client('s3', region_name='us-east-1')
    s3_client.create_bucket(Bucket='test-bucket')

    s3_client.put_public_access_block(
        Bucket='test-bucket',
        PublicAccessBlockConfiguration={
            'BlockPublicAcls': True,
            'IgnorePublicAcls': True,
            'BlockPublicPolicy': True,
            'RestrictPublicBuckets': True
        }
    )

    result = check_public_access_block('test-bucket')

    assert result['status'] == 'PASS'