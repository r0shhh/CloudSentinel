import boto3
from moto import mock_aws
from scanners.ebs_scanner import check_ebs_encryption


@mock_aws
def test_check_ebs_no_volumes():
    result = check_ebs_encryption()

    assert result == []


@mock_aws
def test_check_ebs_unencrypted_volume():
    ec2 = boto3.client('ec2', region_name='us-east-1')

    az = ec2.describe_availability_zones()['AvailabilityZones'][0]['ZoneName']

    ec2.create_volume(
        Size=8,
        AvailabilityZone=az,
        Encrypted=False
    )

    results = check_ebs_encryption()

    assert any(r['status'] == 'FAIL' for r in results)


@mock_aws
def test_check_ebs_encrypted_volume():
    ec2 = boto3.client('ec2', region_name='us-east-1')

    az = ec2.describe_availability_zones()['AvailabilityZones'][0]['ZoneName']

    ec2.create_volume(
        Size=8,
        AvailabilityZone=az,
        Encrypted=True
    )

    results = check_ebs_encryption()

    assert any(r['status'] == 'PASS' for r in results)