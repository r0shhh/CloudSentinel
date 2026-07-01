import os
import pytest

@pytest.fixture(scope="session", autouse=True)
def mock_aws_credentials():
    """
    Globally configures dummy AWS credentials and default region for all tests.
    """

    os.environ["AWS_ACCESS_KEY_ID"] = "mock-access-key"
    os.environ["AWS_SECRET_ACCESS_KEY"] = "mock-secret-key"
    os.environ["AWS_SECURITY_TOKEN"] = "mock-token"
    os.environ["AWS_SESSION_TOKEN"] = "mock-token"
    os.environ["AWS_DEFAULT_REGION"] = "us-east-1"