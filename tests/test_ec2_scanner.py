import boto3
from moto import mock_aws
from scanners.ec2_scanner import check_security_groups


@mock_aws
def test_check_security_groups_no_risky_rules():
    ec2_client = boto3.client('ec2', region_name='us-east-1')
    ec2_client.create_security_group(GroupName='test-sg', Description='test')

    results = check_security_groups(dangerous_ports=[22, 3389, 3306, 5432])

    for result in results:
        assert result['status'] == 'PASS'


@mock_aws
def test_check_security_groups_open_ssh():
    ec2_client = boto3.client('ec2', region_name='us-east-1')
    sg = ec2_client.create_security_group(GroupName='test-sg-open', Description='test')

    ec2_client.authorize_security_group_ingress(
        GroupId=sg['GroupId'],
        IpPermissions=[
            {
                'IpProtocol': 'tcp',
                'FromPort': 22,
                'ToPort': 22,
                'IpRanges': [{'CidrIp': '0.0.0.0/0'}]
            }
        ]
    )

    results = check_security_groups(dangerous_ports=[22, 3389, 3306, 5432])

    assert any(r['status'] == 'FAIL' for r in results)
    


@mock_aws
def test_check_security_groups_restricted_ip():
    ec2_client = boto3.client('ec2', region_name='us-east-1')
    sg = ec2_client.create_security_group(GroupName='test-sg-restricted', Description='test')

    ec2_client.authorize_security_group_ingress(
        GroupId=sg['GroupId'],
        IpPermissions=[
            {
                'IpProtocol': 'tcp',

                'FromPort': 22,

                'ToPort': 22,

                'IpRanges': [{'CidrIp': '203.0.113.50/32'}]
            }
        ]
    )

    results = check_security_groups(dangerous_ports=[22, 3389, 3306, 5432])

    assert all(r['status'] == 'PASS' for r in results)