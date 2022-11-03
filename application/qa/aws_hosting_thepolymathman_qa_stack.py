from aws_cdk import (
    Duration,
    Stack,
    RemovalPolicy,
    SecretValue,
    aws_iam as iam, 
    aws_s3 as s3,
    aws_route53 as r53,
    aws_route53_targets as targets,
    aws_codebuild as codebuild,
    aws_codepipeline as codepipeline,
    aws_codepipeline_actions as cpactions,
    aws_certificatemanager as acm,
    aws_cloudfront as cloudfront,
    aws_cloudfront_origins as origins
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

class AwsHostingThepolymathmanQaStack(Stack):

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
            space = "qa"
            logger.info(space)
        else:
            logger.info(space)


        branchStr = f"/{space}/branch"
        githuburlStr = f"/{space}/spacedata_url"
        githubappownerrepoStr = f"/{space}/spacedata_app_owner_repo"

        # Secrets Manager Names
        spaceStr = f"/{space}"
        githubapptokenStr = f"{spaceStr}/spacedata_app_token"
        ga4trackingIDStr = f"{spaceStr}/spacedata_gatsbycfg_ga4_tracking_id"
        logger.info(ga4trackingIDStr)
    
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

        # Import App (website code) owner/repo
        importedga4trackingIDStr = ssmb3.get_parameter(
            Name=ga4trackingIDStr,
            WithDecryption=True
        )
        ga4trackingID = importedga4trackingIDStr["Parameter"]["Value"]

        #Variables to be used later
        minusroot = Githuburl.split(".")
        minusroot0 = minusroot[0]
        root1 = minusroot[1]
        domain = Githuburl
        subdomain = f"www.{domain}"
        logger.info(f"SAN 1 is {domain}")
        logger.info(f"SAN 2 is {subdomain}")
        domainminusdecimals = f"{minusroot0}{root1}"

        # Create the hosted zone for the domain
        idHZ = f"{domainminusdecimals}HZ"
        domainHZ = r53.HostedZone(self, idHZ,
            zone_name=domain
        )
        iddomainHZ = domainHZ.hosted_zone_id

        # Build the S3 buckets that host the site 
        ids3domain = f"{Branch}{domain}"
        maindomain = s3.Bucket(self, ids3domain,
            bucket_name=domain,
            public_read_access=False,
            removal_policy=remove,
            block_public_access=s3.BlockPublicAccess.BLOCK_ALL
        )
        # Create ACM Certificate for CloudFront distribution.
        idCertificate = f"{domain}-certificate"
        certificate = acm.Certificate(self, idCertificate,
            domain_name=domain,
            subject_alternative_names=[subdomain],
            validation=acm.CertificateValidation.from_dns(domainHZ)
        )
        # Rewrite blog/example to blog/example/index.html, required for Gatsby.
        # https://github.com/aws-samples/amazon-cloudfront-functions/tree/main/url-rewrite-single-page-apps
        idCloudFront = f"{domain}-cloudfrount"
        cloudfront_function = cloudfront.Function(self,idCloudFront,
            code=cloudfront.FunctionCode.from_file(
                file_path=f"application/{space}/cloudfront_function.js"
            ),
        )
        # Add Security Response Headers.
        idSecHeaders = f"{domainminusdecimals}SecHeader"
        response_header_policy = cloudfront.ResponseHeadersPolicy(self,idSecHeaders,
            comment=idSecHeaders,
            response_headers_policy_name=f"{idSecHeaders}Policy",
            security_headers_behavior=cloudfront.ResponseSecurityHeadersBehavior(
                content_security_policy=cloudfront.ResponseHeadersContentSecurityPolicy(
                    # https://stackoverflow.com/questions/34669075/can-content-security-policy-be-made-compatible-with-google-analytics-and-adsense
                    # New allows google on site. 
                    content_security_policy="default-src 'self' googleads.g.doubleclick.net; "
                    "img-src 'self' data: storage.googleapis.com pagead2.googlesyndication.com; child-src 'none'; frame-ancestors 'self'; "
                    "object-src 'none'; "
                    "script-src 'self' 'unsafe-inline' data: pagead2.googlesyndication.com partner.googleadservices.com tpc.googlesyndication.com www.googletagservices.com adservice.google.com adservice.google.ad adservice.google.ae adservice.google.com.af adservice.google.com.ag adservice.google.com.ai adservice.google.al adservice.google.am adservice.google.co.ao adservice.google.com.ar adservice.google.as adservice.google.at adservice.google.com.au adservice.google.az adservice.google.ba adservice.google.com.bd adservice.google.be adservice.google.bf adservice.google.bg adservice.google.com.bh adservice.google.bi adservice.google.bj adservice.google.com.bn adservice.google.com.bo adservice.google.com.br adservice.google.bs adservice.google.bt adservice.google.co.bw adservice.google.by adservice.google.com.bz adservice.google.ca adservice.google.cd adservice.google.cf adservice.google.cg adservice.google.ch adservice.google.ci adservice.google.co.ck adservice.google.cl adservice.google.cm adservice.google.cn adservice.google.com.co adservice.google.co.cr adservice.google.com.cu adservice.google.cv adservice.google.com.cy adservice.google.cz adservice.google.de adservice.google.dj adservice.google.dk adservice.google.dm adservice.google.com.do adservice.google.dz adservice.google.com.ec adservice.google.ee adservice.google.com.eg adservice.google.es adservice.google.com.et adservice.google.fi adservice.google.com.fj adservice.google.fm adservice.google.fr adservice.google.ga adservice.google.ge adservice.google.gg adservice.google.com.gh adservice.google.com.gi adservice.google.gl adservice.google.gm adservice.google.gr adservice.google.com.gt adservice.google.gy adservice.google.com.hk adservice.google.hn adservice.google.hr adservice.google.ht adservice.google.hu adservice.google.co.id adservice.google.ie adservice.google.co.il adservice.google.im adservice.google.co.in adservice.google.iq adservice.google.is adservice.google.it adservice.google.je adservice.google.com.jm adservice.google.jo adservice.google.co.jp adservice.google.co.ke adservice.google.com.kh adservice.google.ki adservice.google.kg adservice.google.co.kr adservice.google.com.kw adservice.google.kz adservice.google.la adservice.google.com.lb adservice.google.li adservice.google.lk adservice.google.co.ls adservice.google.lt adservice.google.lu adservice.google.lv adservice.google.com.ly adservice.google.co.ma adservice.google.md adservice.google.me adservice.google.mg adservice.google.mk adservice.google.ml adservice.google.com.mm adservice.google.mn adservice.google.ms adservice.google.com.mt adservice.google.mu adservice.google.mv adservice.google.mw adservice.google.com.mx adservice.google.com.my adservice.google.co.mz adservice.google.com.na adservice.google.com.ng adservice.google.com.ni adservice.google.ne adservice.google.nl adservice.google.no adservice.google.com.np adservice.google.nr adservice.google.nu adservice.google.co.nz adservice.google.com.om adservice.google.com.pa adservice.google.com.pe adservice.google.com.pg adservice.google.com.ph adservice.google.com.pk adservice.google.pl adservice.google.pn adservice.google.com.pr adservice.google.ps adservice.google.pt adservice.google.com.py adservice.google.com.qa adservice.google.ro adservice.google.ru adservice.google.rw adservice.google.com.sa adservice.google.com.sb adservice.google.sc adservice.google.se adservice.google.com.sg adservice.google.sh adservice.google.si adservice.google.sk adservice.google.com.sl adservice.google.sn adservice.google.so adservice.google.sm adservice.google.sr adservice.google.st adservice.google.com.sv adservice.google.td adservice.google.tg adservice.google.co.th adservice.google.com.tj adservice.google.tl adservice.google.tm adservice.google.tn adservice.google.to adservice.google.com.tr adservice.google.tt adservice.google.com.tw adservice.google.co.tz adservice.google.com.ua adservice.google.co.ug adservice.google.co.uk adservice.google.com.uy adservice.google.co.uz adservice.google.com.vc adservice.google.co.ve adservice.google.vg adservice.google.co.vi adservice.google.com.vn adservice.google.vu adservice.google.ws adservice.google.rs adservice.google.co.za adservice.google.co.zm adservice.google.co.zw adservice.google.cat; "
                    "style-src 'unsafe-inline' 'self'; font-src 'self' fonts.googleapis.com; "
                    "frame-src www.youtube-nocookie.com;",
                    # Old, blocks google ads
                    # content_security_policy="default-src 'self'; "
                    # "img-src 'self' data: https://*; child-src 'none'; "
                    # "object-src 'none'; script-src 'unsafe-inline' 'self' 'unsafe-eval'; "
                    # "style-src 'unsafe-inline' 'self'; font-src 'self' data:; "
                    # "frame-src www.youtube-nocookie.com;",

                    # From StackOverFlow
                    # default-src 'self' googleads.g.doubleclick.net;
                    # script-src 'self' 'unsafe-inline' data: pagead2.googlesyndication.com storage.googleapis.com googleads.g.doubleclick.net ajax.googleapis.com; 
                    # img-src 'self' data: storage.googleapis.com pagead2.googlesyndication.com; 
                    # style-src 'self' 'unsafe-inline'; 
                    # font-src 'self' fonts.googleapis.com; frame-ancestors 'self'; object-src 'self'
                    override=True,
                ),
                content_type_options=cloudfront.ResponseHeadersContentTypeOptions(
                    override=True
                ),
                frame_options=cloudfront.ResponseHeadersFrameOptions(
                    frame_option=cloudfront.HeadersFrameOption.DENY, override=True
                ),
                referrer_policy=cloudfront.ResponseHeadersReferrerPolicy(
                    referrer_policy=cloudfront.HeadersReferrerPolicy.NO_REFERRER,
                    override=True,
                ),
                strict_transport_security=cloudfront.ResponseHeadersStrictTransportSecurity(
                    access_control_max_age=Duration.seconds(63072000),
                    include_subdomains=True,
                    override=True,
                    preload=True,
                ),
                xss_protection=cloudfront.ResponseHeadersXSSProtection(
                    protection=True,
                    mode_block=True,
                    override=True,
                ),
            ),
        )
        # Create CloudFront Distribution
        idCloudFrontDistribution = f"{domain}-cloudfrontdistribution"
        distribution = cloudfront.Distribution(self,idCloudFrontDistribution,
            certificate=certificate,
            error_responses=[
                cloudfront.ErrorResponse(
                    http_status=403,
                    response_http_status=404,
                    response_page_path="/404.html",
                )
            ],
            default_behavior=cloudfront.BehaviorOptions(
                origin=origins.S3Origin(maindomain),
                function_associations=[
                    cloudfront.FunctionAssociation(
                        function=cloudfront_function,
                        event_type=cloudfront.FunctionEventType.VIEWER_REQUEST,
                    )
                ],
                viewer_protocol_policy=cloudfront.ViewerProtocolPolicy.REDIRECT_TO_HTTPS,
                response_headers_policy=response_header_policy,
                cache_policy=cloudfront.CachePolicy.CACHING_DISABLED
            ),
            domain_names=[domain,subdomain],
            minimum_protocol_version=cloudfront.SecurityPolicyProtocol.TLS_V1_2_2021
            #geo_restriction=cloudfront.GeoRestriction.allowlist("US","CA","IN","JP")
        )
        # Create Domain Records.
        # ipv4 Records.
        idARecordDomain = f"{domain}ARECORD"
        r53.ARecord(self,idARecordDomain,
            zone=domainHZ,
            record_name=domain,
            target=r53.RecordTarget.from_alias(
                targets.CloudFrontTarget(distribution)
            ),
        )
        # ipv6 Records.
        idAAAARecordDomain = f"{domain}AAAARECORD"
        r53.AaaaRecord(self,idAAAARecordDomain,
            zone=domainHZ,
            record_name=domain,
            target=r53.RecordTarget.from_alias(
                targets.CloudFrontTarget(distribution)
            ),
        )

        # ipv4 Records.
        idARecordDomain = f"{subdomain}ARECORD"
        r53.ARecord(self,idARecordDomain,
            zone=domainHZ,
            record_name=subdomain,
            target=r53.RecordTarget.from_alias(
                targets.CloudFrontTarget(distribution)
            ),
        )
        # ipv6 Records.
        idAAAARecordDomain = f"{subdomain}AAAARECORD"
        r53.AaaaRecord(self,idAAAARecordDomain,
            zone=domainHZ,
            record_name=subdomain,
            target=r53.RecordTarget.from_alias(
                targets.CloudFrontTarget(distribution)
            ),
        )

        # Build the CodePipeline CodeBuild for Gatsby 
        # Build Artifacts
        outputSources = codepipeline.Artifact()
        outputWebsite = codepipeline.Artifact()
        # Retrieve Secrets
        stateSecretVal = SecretValue.secrets_manager(githubapptokenStr)

        # Set Trigger
        ghtrigger = cpactions.GitHubTrigger("WEBHOOK")
        # Name Pipeline
        idwebPipeline = f"web{domainminusdecimals}{space}"
        # Initialize Pipeline
        pipeline = codepipeline.Pipeline(self, idwebPipeline,
            pipeline_name=idwebPipeline,
            restart_execution_on_update=True
        )
        # Split Owner and Repo
        ownerrepo = Githubappownerrepo.split("/")
        logger.info(ownerrepo)
        owner = ownerrepo[0]
        logger.info(owner)
        repo = ownerrepo[1]
        logger.info(repo)
        pipeline.add_stage(
            stage_name="Source",
            actions=[cpactions.GitHubSourceAction(
                action_name="Checkout",
                owner=owner,
                repo=repo,
                branch=Branch,
                oauth_token=stateSecretVal,
                output=outputSources,
                trigger=ghtrigger
            )]
        )
        idGatsbyPipeline = f"gatsby{domainminusdecimals}{space}"
        build_environment = codebuild.BuildEnvironment(
            build_image=codebuild.LinuxBuildImage.from_code_build_image_id(id="aws/codebuild/amazonlinux2-x86_64-standard:4.0"),
            environment_variables={
                "GITHUBURL": codebuild.BuildEnvironmentVariable(
                    value=Githuburl
                ),
                "G4ANALYTICS": codebuild.BuildEnvironmentVariable(
                    value=ga4trackingID
                )
            }
        )
        buildGatsby = codebuild.PipelineProject(self, idGatsbyPipeline,
            environment=build_environment,
            build_spec=codebuild.BuildSpec.from_object({
                "version": "0.2",
                "phases": {
                    "install": {
                        "runtime-versions": {"nodejs": "16"},
                        "commands": ["touch .npmignore",
                        "sed -i \"s/GA-TRACKING_ID/$G4ANALYTICS/g\" gatsby-config.js",
                        "npm install -g gatsby",
                        "ls -al"
                        ]
                    },
                    "pre_build": {
                        "commands": ["ls -al","npm install"]
                    },
                    "build": {
                        "commands": ["ls -al",
                        "npm run build",
                        "ls -al"
                        ]
                    },
                    "post_build": {
                        "commands": ["aws s3 sync public/ s3://$GITHUBURL --delete"]
                    },
                },
                "env": {
                    "shell": "bash"
                },
                "artifacts":{
                    "base-directory": "public",
                    "files": '**/*',
                    "discard-paths": "yes"
                }                    
            }
            )
        )
        codeBuildPolicyStatement = iam.PolicyStatement(
            effect=iam.Effect.ALLOW,
            actions=[
                "s3:PutObject",
                "s3:PutObjectAcl",
                "s3:GetObject",
                "s3:GetObjectAcl",
                "s3:DeleteObject",
                "s3:ListBucket",
                "s3:ListBucketMultipartUploads",
                "s3:AbortMultipartUpload",
                "s3:ListMultipartUploadParts",
                "s3:PutAccountPublicAccessBlock",
                "s3:GetAccountPublicAccessBlock",
                "s3:ListAllMyBuckets",
                "s3:HeadBucket",
                "secretsmanager:GetSecretValue",
                "ssm:GetParameters"
            ],
            resources=["*"]
        )
        buildGatsby.add_to_role_policy(codeBuildPolicyStatement)
        pipeline.add_stage(
            stage_name="BuildWebsite",
            actions=[cpactions.CodeBuildAction(
                action_name="BuildGatsbyArtifacts",
                project=buildGatsby,
                input=outputSources,
                outputs=[outputWebsite],
                run_order=1,
                check_secrets_in_plain_text_env_variables=False
            )
            ]
        )