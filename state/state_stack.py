import json 
import boto3
import base64
import logging 
import sys
from botocore.exceptions import ClientError
from aws_cdk import (
    Stack,
    CfnOutput,
    RemovalPolicy, 
    aws_ssm as ssm
)
from constructs import Construct

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

class AwsHostingStateStack(Stack):

    def __init__(self, scope: Construct, construct_id: str, **kwargs) -> None:
        super().__init__(scope, construct_id, **kwargs)

        smb3 = boto3.client("secretsmanager")
        ssmb3 = boto3.client("ssm")


        # Set Removal Policy
        retain = RemovalPolicy.RETAIN
        remove = RemovalPolicy.DESTROY

        # Retrieve State Values from Secrets Manager, put into SSM and Secrets Manager

        state_secret_name = "state-json"

        try:
            get_secret_value_response = smb3.get_secret_value(
                SecretId=state_secret_name
            )
        except ClientError as e:
            if e.response['Error']['Code'] == 'DecryptionFailureException':
                # Secrets Manager can't decrypt the protected secret text using the provided KMS key.
                # Deal with the exception here, and/or rethrow at your discretion.
                raise e
            elif e.response['Error']['Code'] == 'InternalServiceErrorException':
                # An error occurred on the server side.
                # Deal with the exception here, and/or rethrow at your discretion.
                raise e
            elif e.response['Error']['Code'] == 'InvalidParameterException':
                # You provided an invalid value for a parameter.
                # Deal with the exception here, and/or rethrow at your discretion.
                raise e
            elif e.response['Error']['Code'] == 'InvalidRequestException':
                # You provided a parameter value that is not valid for the current state of the resource.
                # Deal with the exception here, and/or rethrow at your discretion.
                raise e
            elif e.response['Error']['Code'] == 'ResourceNotFoundException':
                # We can't find the resource that you asked for.
                # Deal with the exception here, and/or rethrow at your discretion.
                raise e
        else:
            # Decrypts secret using the associated KMS key.
            # Depending on whether the secret is a string or binary, one of these fields will be populated.
            if 'SecretString' in get_secret_value_response:
                secret = get_secret_value_response['SecretString']
            else:
                secret = base64.b64decode(get_secret_value_response['SecretBinary'])

        json_data = json.loads(secret)
        

        # json_data is a list of dicts
        # logger.info(type(json_data['environment']))
        list = json_data['environment']
        i=0
        spacelist = []        
        for dic in list:
            for key, value in dic.items():
                if key == 'branch':
                    space_name = dic['space']
                    param_name_space_branch = f"/{space_name}/branch"
                    ssmresponse = ssmb3.put_parameter(
                        Name=param_name_space_branch,
                        Value=value,
                        Type='String',
                        Overwrite=True
                    )
                if key == 'space':
                    spacedic = {"space":value}
                    spacelist.append(spacedic)
                if key == 'priority':
                    if value == '2':
                        spaceBootStrap = (dic['space'])
                        param_name_space_priority = '/lowpriority' 
                        ssmresponse = ssmb3.put_parameter(
                            Name=param_name_space_priority,
                            Value=spaceBootStrap,
                            Type='String',
                            Overwrite=True
                        )                  
                if key == 'spacedata':
                    # dic is dict
                    # value is list
                    for key1 in value:
                        # key1 is a dict
                        space_name = dic['space']
                        param_name_base = f"/{space_name}/spacedata"
                        for key2 in key1:
                            param_name = f"{param_name_base}_{key2}"
                            # Put tokens in Secrets Manager
                            if key2.__contains__("token"):
                                # See if it exists first:
                                try:
                                    exists_response = smb3.describe_secret(
                                        SecretId=param_name
                                        )
                                except:
                                    response = smb3.create_secret(
                                        Name=param_name,
                                        SecretString=key1[key2],
                                        ForceOverwriteReplicaSecret=True
                                    )
                                else:
                                    logger.info(exists_response)
                                    response = smb3.update_secret(
                                        SecretId=param_name,
                                        SecretString=key1[key2]
                                    )
                            else:                                
                                listorstring = key1[key2]
                                if type(listorstring) == str:
                                    logger.info(f"{type(listorstring)} is the type, str")
                                    ssmresponse = ssmb3.put_parameter(
                                        Name=param_name,
                                        Value=key1[key2],
                                        Type='String',
                                        Overwrite=True
                                    )  
                                else:
                                    logger.info(listorstring)
                                    logger.info(f"{type(listorstring)} is the type, list")
                                    new_list = (", ".join( repr(e) for e in listorstring))
                                    logger.info(new_list)
                                    ssmresponse = ssmb3.put_parameter(
                                        Name=param_name,
                                        Value=new_list,
                                        Type='String',
                                        Overwrite=True
                                    )                             
        spacelist = json.dumps(spacelist)
        spaceresponse = ssmb3.put_parameter(
            Name="space_list",
            Value=spacelist,
            Type='String',
            Overwrite=True
        )