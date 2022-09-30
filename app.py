#!/usr/bin/env python3
#imports first
import json
import boto3
import logging
import sys
#from imports
from aws_cdk import App, Environment
#from import Stacks
from state.state_stack import AwsHostingStateStack
from cdk_pipeline.prod.cdk_pipeline_stack_prod import AwsHostingCDKPipelineProdStack
from cdk_pipeline.qa.cdk_pipeline_stack_qa import AwsHostingCDKPipelineQaStack
from aws_hosting_thepolymathman.aws_hosting_thepolymathman_stack import AwsHostingThepolymathmanStack
from application.prod.aws_hosting_thepolymathman_prod_stack import AwsHostingThepolymathmanProdStack
from application.qa.aws_hosting_thepolymathman_qa_stack import AwsHostingThepolymathmanQaStack

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

# Build environment, to be used if deployed to numerous AWS Accounts with Creds already stored in pipeline tool  
# This also helps with SSM puts and gets. 
account_id = boto3.client("sts").get_caller_identity()["Account"]
logger.info(account_id)
session = boto3.session.Session()
region = session.region_name
logger.info(region)
env = Environment(account = account_id, region = region)

app = App()
# Build State First
AwsHostingStateStack(app, "AwsHostingStateStack", env=env)
# Deploy CDK Pipeline's based on State
AwsHostingCDKPipelineQaStack(app, "AwsHostingCDKPipelineQaStack", env=env)
AwsHostingCDKPipelineProdStack(app, "AwsHostingCDKPipelineProdStack", env=env)
# Deploy Infrastructure that supports Web Application
AwsHostingThepolymathmanQaStack(app, "AwsHostingThepolymathmanQaStack", env=env)
AwsHostingThepolymathmanProdStack(app, "AwsHostingThepolymathmanProdStack", env=env)

app.synth()
