import boto3
from moto import mock_aws
from scanners.rds_scanner import check_rds_public_access


@mock_aws
def test_check_rds_no_instances():
    rds_client = boto3.client('rds', region_name='us-east-1')

    result = check_rds_public_access()

    assert result == []


@mock_aws
def test_check_rds_public_instance():
    rds_client = boto3.client('rds', region_name='us-east-1')

    rds_client.create_db_instance(
        DBInstanceIdentifier='vulnerable-db',
        DBInstanceClass='db.t3.micro',
        Engine='postgres',
        PubliclyAccessible=True
    )

    results = check_rds_public_access ()
    assert any (r['status'] == 'FAIL' for r in results)


@mock_aws
def test_check_rds_private_instance():
    rds_client = boto3.client('rds', region_name='us-east-1')

    rds_client.create_db_instance(
        DBInstanceIdentifier='secure-db',
        DBInstanceClass='db.t3.micro',
        Engine='postgres',
        PubliclyAccessible=False
    )

    results = check_rds_public_access ()
    assert any (r['status'] == 'PASS' for r in results)
