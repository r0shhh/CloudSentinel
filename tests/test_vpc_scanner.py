import os
os.environ["AWS_DEFAULT_REGION"] = "us-east-1"
import boto3
from moto import mock_aws
from scanners.vpc_scanner import check_vpc_flow_logs

@mock_aws
def test_check_vpc_flow_logs_disabled():
    ec2_client = boto3.client('ec2', region_name='us-east-1')

    vpc_response = ec2_client.create_vpc(
        CidrBlock='10.0.0.0/16'
    )

    vpc_id = vpc_response['Vpc']['VpcId']

    results = check_vpc_flow_logs()

    target_result = next((r for r in results if r['vpc_id'] == vpc_id), None)
    assert target_result is not None
    assert target_result['status'] == 'FAIL'


@mock_aws
def test_check_vpc_flow_logs_enabled():
    ec2_client = boto3.client('ec2', region_name='us-east-1')

    vpc_response = ec2_client.create_vpc(
        CidrBlock='10.0.0.0/16'
    )
    vpc_id = vpc_response['Vpc']['VpcId']

    ec2_client.create_flow_logs(
        ResourceIds=[vpc_id],
        ResourceType='VPC',
        TrafficType='ALL',
        LogDestinationType='cloud-watch-logs',
        LogGroupName='test-log-group',
        DeliverLogsPermissionArn='arn:aws:iam::123456789012:role/test-role'

    )

    results = check_vpc_flow_logs()

    target_result = next((r for r in results if r['vpc_id'] == vpc_id), None)
    assert target_result is not None
    assert target_result['status'] == 'PASS'
