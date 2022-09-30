from aws_cdk import (
    Fn,
    Stack,
    Tags,
    RemovalPolicy,
    SecretValue,
    aws_secretsmanager as secretsmanager,
    aws_codepipeline_actions as cpactions,
    aws_iam as iam
)
from aws_cdk.pipelines import CodePipeline, CodePipelineSource, ShellStep, CodeBuildStep
from constructs import Construct
import boto3
import json
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

class AwsHostingCDKPipelineProdStack(Stack):

    def __init__(self, scope: Construct, construct_id: str, **kwargs) -> None:
        super().__init__(scope, construct_id, **kwargs)

        # Boto3 Clients to be called
        ssmb3 = boto3.client("ssm")
        # External Functions

        # Set Removal Policy
        retain = RemovalPolicy.RETAIN
        remove = RemovalPolicy.DESTROY
  
        # import Space for values in SSM
        space_context = self.node.try_get_context("space")
        space = str(space_context)

        # Get bootstrapping Space
        if space == "None":
            space = "prod"
            logger.info(space)
        else:
            logger.info(space)

        branchStr = f"/{space}/branch"
        githuburlStr = f"/{space}/spacedata_url"
        githubappownerrepoStr = f"/{space}/spacedata_app_owner_repo"
        githubcdkhostingownerrepoStr = f"/{space}/spacedata_cdk_hosting_owner_repo"
        codebuildstepcommandStr = f"/{space}/spacedata_code_build_step_commands"
        iampolicystatementStr = f"/{space}/spacedata_cdk_pipeline_iam_policystatement"

        # Secrets Manager Names
        spaceStr = f"/{space}"
        githubcdkhostingtokenStr = f"{spaceStr}/spacedata_cdk_hosting_token"

        # Import Branch
        importedBranch = ssmb3.get_parameter(
            Name=branchStr,
            WithDecryption=True
        )
        Branch = importedBranch["Parameter"]["Value"]
        logger.info(Branch)

        # Import URL
        importedGithuburl = ssmb3.get_parameter(
            Name=githuburlStr,
            WithDecryption=True
        )
        Githuburl = importedGithuburl["Parameter"]["Value"]
        logger.info(Githuburl)

        # Import App (website code) owner/repo
        importedGithubappownerrepo = ssmb3.get_parameter(
            Name=githubappownerrepoStr,
            WithDecryption=True
        )
        Githubappownerrepo = importedGithubappownerrepo["Parameter"]["Value"]
        logger.info(Githubappownerrepo)

        # Import CDK Hosting owner/repo
        importedGithubcdkhostingownerrepo = ssmb3.get_parameter(
            Name=githubcdkhostingownerrepoStr,
            WithDecryption=True
        )
        Githubcdkhostingownerrepo = importedGithubcdkhostingownerrepo["Parameter"]["Value"]
        logger.info(Githubcdkhostingownerrepo)

        # Import IAM Policy Statement String
        importedIAMPolicyStatementString = ssmb3.get_parameter(
            Name=iampolicystatementStr,
            WithDecryption=True
        )
        IAMPolicyStatementString = importedIAMPolicyStatementString["Parameter"]["Value"]
        replaceIAMList = IAMPolicyStatementString.replace("'","")
        IAMList = replaceIAMList.split(",")
        IAMList = [i.strip(" ") for i in IAMList]
        logger.info(IAMList)

        # Import Code Build Step Command String
        importedCodebuildstepcommandString = ssmb3.get_parameter(
            Name=codebuildstepcommandStr,
            WithDecryption=True
        )
        CodebuildstepcommandString = importedCodebuildstepcommandString["Parameter"]["Value"]
        replacecommandList = CodebuildstepcommandString.replace("'","")
        commandList = replacecommandList.split(",")
        commandList = [i.strip(" ") for i in commandList]
        logger.info(commandList)

        #Variables to be used later
        minusroot = Githuburl.split(".")
        minusroot0 = minusroot[0]
        root1 = minusroot[1]
        domain = Githuburl
        subdomain = f"www.{domain}"
        domainminusdecimals = f"{minusroot0}{root1}"

        # Create Pipelines
        # Retrieve Secret
        stateSecretVal = SecretValue.secrets_manager(githubcdkhostingtokenStr)
        # Set Trigger
        ghtrigger = cpactions.GitHubTrigger("WEBHOOK")
        # Create Policy Statement to Access Secrets Manager
        codePipelinePolicyStatement = iam.PolicyStatement(
            effect=iam.Effect.ALLOW,
            actions=IAMList,
            resources=["*"]
        )

        idHostPipeline = f"cdkPipe{domainminusdecimals}{space}"
        CodePipeline(self, idHostPipeline, 
            pipeline_name=idHostPipeline,
            synth=CodeBuildStep("Deploy", 
                input=CodePipelineSource.git_hub(Githubcdkhostingownerrepo, Branch,
                    authentication=stateSecretVal,
                    trigger=ghtrigger
                ),
                commands=commandList,
                role_policy_statements=[codePipelinePolicyStatement]
            )
        )
