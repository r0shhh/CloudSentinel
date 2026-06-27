import os
os.environ["AWS_DEFAULT_REGION"] = "us-east-1"
import boto3
from moto import mock_aws
from scanners.cloudtrail_scanner import check_cloudtrail


@mock_aws
def test_check_cloudtrail_no_trails():
    cloudtrail_client = boto3.client('cloudtrail')
   
    results = check_cloudtrail()
    assert any(r['status'] == 'FAIL' for r in results)


@mock_aws
def test_check_cloudtrail_compliant():
    s3_client = boto3.client('s3', region_name='us-east-1')
    s3_client.create_bucket(Bucket='test-cloudtrail-logs')

    cloudtrail_client = boto3.client('cloudtrail', region_name='us-east-1')
    cloudtrail_client.create_trail(
        Name='test-trail',
        S3BucketName='test-cloudtrail-logs',
        IsMultiRegionTrail= True
    )
    cloudtrail_client.start_logging(Name='test-trail')

    results = check_cloudtrail()
    assert any(r['status'] == 'PASS' for r in results)


@mock_aws
def test_check_cloudtrail_not_logging():
    s3_client = boto3.client('s3', region_name='us-east-1')
    s3_client.create_bucket(Bucket='test-cloudtrail-logs')

    cloudtrail_client = boto3.client('cloudtrail', region_name='us-east-1')
    cloudtrail_client.create_trail(
        Name='test-trail',
        S3BucketName='test-cloudtrail-logs',
        IsMultiRegionTrail= True
    )

    results = check_cloudtrail()
    assert any(r['status'] == 'FAIL' for r in results)


@mock_aws
def test_check_cloudtrail_not_multi_region():
    s3_client = boto3.client('s3', region_name='us-east-1')
    s3_client.create_bucket(Bucket='test-cloudtrail-logs')

    cloudtrail_client = boto3.client('cloudtrail', region_name='us-east-1')
    cloudtrail_client.create_trail(
        Name='test-trail',
        S3BucketName='test-cloudtrail-logs',
        IsMultiRegionTrail= False
    )

    cloudtrail_client.start_logging(Name='test-trail')

    results = check_cloudtrail()
    assert any(r['status'] == 'FAIL' for r in results)