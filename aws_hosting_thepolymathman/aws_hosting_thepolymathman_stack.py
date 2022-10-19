from aws_cdk import (
    Stack,
    RemovalPolicy,
)
from constructs import Construct
import boto3
import logging
import sys

# Set logging level and use this instead of printing
# From:
# https://stackoverflow.com/questions/14058453/making-python-loggers-output-all-messages-to-stdout-in-addition-to-log-file
stdout_handler = logging.StreamHandler(stream=sys.stdout)
handlers = [stdout_handler]

logging.basicConfig(
    level=logging.INFO, 
    format='[%(asctime)s] {%(filename)s:%(lineno)d} %(levelname)s - %(message)s',
    handlers=handlers
)
logger = logging.getLogger('CDK_LOGS')

class AwsHostingThepolymathmanStack(Stack):

    def __init__(self, scope: Construct, construct_id: str, **kwargs) -> None:
        super().__init__(scope, construct_id, **kwargs)

        # Boto3 Clients to be called
        ssmb3 = boto3.client("ssm")
        # External Functions

        # Set Removal Policy
        retain = RemovalPolicy.RETAIN
        remove = RemovalPolicy.DESTROY