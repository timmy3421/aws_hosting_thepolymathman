# ReadMe

# IaC
This page describes/explains/documents the technical details, practices and how-to of building these sites.

[Prod Site -  thepolymathman.io](https://www.thepolymathman.io)

[QA Site - the polymathman.com](https://www.thepolymathman.com)

This can also be read here:
### Read IaC Documentation Here:
[IaC Documentation for both sites](https://www.thepolymathman.io/about-this-site-iac)

### Read Software CI/CD Documentation Here:
[Software CI/CD Documentation for both sites](https://www.thepolymathman.io/about-this-site-cicd)

### Code Repo(s):  
https://github.com/timmy3421/aws_hosting_thepolymathman


### Technologies Covered:  
- AWS CDK using Python
- AWS SSM (stores state for QA and Prod)
- AWS Secrets Manager (stores secrets for QA and Prod)
- AWS CloudFront
- AWS ACM
- AWS Route53
- AWS S3
- Github
- AWS CodePipeline
- AWS CDK Pipeline
- AWS Tags


### Explained
The Polymathman site is a static site build using Gatsby. Static sites can be housed in S3 with Cloudfront. The IaC is built with the AWS CDK in Python. 
All AWS CDK examples on this site will be in Python due to the large number of TypeScript examples on the internet. 

The problem: there aren't enough Python examples. 

The goal of this documentation and code is to provide a complete project, one people can actively reference as "another way" to do things. 

#### **It is not "the way", but rather,"another way".**

### **This is also not a "hello world" Journal/Blog. It is "real world"**

We, the authors, want to give back to all those that have contributed on stackforce and other sites
 as code examples. The Polymathman will show many examples of how to use numerous services, how to work with them and how to code for them. 
 
 Examples, live examples. 
 
 "real world" 

 If the site is down, well, look at the code and guess why. 
 
 Maybe, I approved a change that I didn't test thoroughly. 
 
 All commits will be seen. 
 
 #### **All mistakes.**
 
 ### **All successes.**

> An Ideal: The internet is full of "hello world". This is "real world". 


## We first, (manually), deploy state values in AWS Secrets Manager 
We are not fans of manual work. 

The purpose of this project is to code, commit, let the automation do the rest. That being said, we have 2 manual steps to protect our secrets and to kick off this project. Here are our manual steps:

1. This CDK Project pulls state from AWS Secrets Manager. It pulls state from a json string. An example of this json string is stored in the dummystate.json file.
   It is included in the root of this repo. I manually put this in AWS Secrets Manager with the name "state-json". 
   dummystate.json template/example:
    ```json
    {
        "environment":[
            {
                "branch":"main",
                "space":"prod",
                "priority":"1",
                "spacedata":[
                    {
                        "url":"thepolymathman.io",
                        "app_token":"GITHUB_PERSONAL_ACCESS_TOKEN",
                        "app_owner_repo":"timmy3421/thepolymathman",
                        "cdk_hosting_token":"GITHUB_PERSONAL_ACCESS_TOKEN",
                        "cdk_hosting_owner_repo":"timmy3421/aws_hosting_thepolymathman",
                        "code_build_step_commands":["npm install -g aws-cdk", 
                            "python -m pip install -r requirements.txt",
                            "cdk deploy AwsHostingThepolymathmanProdStack --context space=prod --require-approval never"
                        ],
                        "cdk_pipeline_iam_policystatement":[
                            "secretsmanager:*",
                            "s3:*",
                            "cloudformation:CreateChangeSet",
                            "cloudformation:DescribeChangeSet",
                            "cloudformation:DescribeStackResource",
                            "cloudformation:DescribeStacks",
                            "cloudformation:DeleteStack",
                            "cloudformation:ExecuteChangeSet",
                            "cloudformation:DeleteChangeSet",
                            "cloudformation:DescribeStackEvents",
                            "cloudformation:GetTemplate",
                            "ec2:DescribeSecurityGroups",
                            "ec2:DescribeSubnets",
                            "ec2:DescribeVpcs",
                            "ecr:SetRepositoryPolicy",
                            "ecr:GetLifecyclePolicy",
                            "ecr:PutImageTagMutability",
                            "ecr:DescribeRepositories",
                            "ecr:ListTagsForResource",
                            "iam:GetRole",
                            "iam:PassRole",
                            "kms:DescribeKey",
                            "kms:ListAliases",
                            "kms:ListKeys",
                            "lambda:ListFunctions",
                            "tag:GetResources",
                            "ssm:GetParameter",
                            "ssm:GetParameters",
                            "ssm:PutParameter"
                        ],
                        "gatsbycfg_ga4_tracking_id":"G-XXXXXXXXXX"
                    }
                    ]
            },
            {
                "branch":"qa",
                "space":"qa",
                "priority":"2",
                "spacedata":[
                    {
                        "url":"thepolymathman.com",
                        "app_token":"GITHUB_PERSONAL_ACCESS_TOKEN",
                        "app_owner_repo":"timmy3421/thepolymathman",
                        "cdk_hosting_token":"GITHUB_PERSONAL_ACCESS_TOKEN",
                        "cdk_hosting_owner_repo":"timmy3421/aws_hosting_thepolymathman",
                        "code_build_step_commands":["npm install -g aws-cdk", 
                        "python -m pip install -r requirements.txt",
                        "cdk deploy AwsHostingThepolymathmanQaStack --context space=qa --require-approval never"
                        ],
                        "cdk_pipeline_iam_policystatement":[
                            "secretsmanager:*",
                            "s3:*",
                            "cloudformation:CreateChangeSet",
                            "cloudformation:DescribeChangeSet",
                            "cloudformation:DescribeStackResource",
                            "cloudformation:DescribeStacks",
                            "cloudformation:DeleteStack",
                            "cloudformation:ExecuteChangeSet",
                            "cloudformation:DeleteChangeSet",
                            "cloudformation:DescribeStackEvents",
                            "cloudformation:GetTemplate",
                            "ec2:DescribeSecurityGroups",
                            "ec2:DescribeSubnets",
                            "ec2:DescribeVpcs",
                            "ecr:SetRepositoryPolicy",
                            "ecr:GetLifecyclePolicy",
                            "ecr:PutImageTagMutability",
                            "ecr:DescribeRepositories",
                            "ecr:ListTagsForResource",
                            "iam:GetRole",
                            "iam:PassRole",
                            "kms:DescribeKey",
                            "kms:ListAliases",
                            "kms:ListKeys",
                            "lambda:ListFunctions",
                            "tag:GetResources",
                            "ssm:GetParameter",
                            "ssm:GetParameters",
                            "ssm:PutParameter"
                        ],
                        "gatsbycfg_ga4_tracking_id":"G-XXXXXXXXXX"
                    }
                    ]
            }
            ]
    }
    ```
2. The second manual step is deploying this project, once, using the following command from the command line:
   ```python
        cdk deploy AwsHostingStateStack AwsHostingCDKPipelineQaStack AwsHostingCDKPipelineProdStack --require-approval never
   ```

### What just happened (Coding Explained)?

When we run "cdk deploy --all" to deploy any CDK project it deploys all Stacks that are in the app.py file. 
Example from our app.py file:

```python
    # Build State First
    AwsHostingStateStack(app, "AwsHostingStateStack", env=env)
    # Deploy CDK Pipeline's based on State
    AwsHostingCDKPipelineQaStack(app, "AwsHostingCDKPipelineQaStack", env=env)
    AwsHostingCDKPipelineProdStack(app, "AwsHostingCDKPipelineProdStack", env=env)
    # Deploy Infrastructure that supports Web Application
    AwsHostingThepolymathmanQaStack(app, "AwsHostingThepolymathmanQaStack", env=env)
    AwsHostingThepolymathmanProdStack(app, "AwsHostingThepolymathmanProdStack", env=env)
```

### **AwsHostingStateStack** 

In order to explain the first stack that gets processed, **"AwsHostingStateStack"**, we must discuss "the why and the how". 

Why are we defining state and how? 

In this Stack, we use boto3, to import state values from the AWS Secrets Manager secret named "state-json". 
This json string is iterated and all values are stored in the AWS Parameter Store and the AWS Secrets Manager. This is by design.
This is so the CDK Pipelines, that are provisioned in the next stack, can each have their own environment for changes to the Web Application Stack. 
We call each of these environments a "Space". We use "Space" because the word "environment" is used too much in many technologies and languages,
including AWS's CDK. 

A "Space" example would be "qa" or "prod". 

"Space" should be considered the primary key of this project. 

This is by design. Each stack requires the "Space" and then builds its data structures off of this primary key. 

We, also, wanted examples of how to deal with json objects, lists and dictionaries within a CDK project. The JSON library is, by default, included within aws-cdk-lib. Understanding the JSON library and how to work with it using loads and dumps, knowing the difference between both, is crucial in becoming a well-rounded DevOps coder. Why do we say this? Every api request/response, when using boto3 inside of Lambda or within the CDK, returns a JSON object. The request requires the same format. Knowing how to get keys and values from the dictionaries and lists full of dictionaries is so important. This project will provide many examples of how to, easily, get these keys/values so we can use them for our automation. 

We digress. 

Each Space requires it's own secrets and values. This is so the code can remain agnostic, regardless of which Space 
is being changed/provisioned/deployed. In the next stack this will make more sense. 

> How many times have we heard the excuse:  
> "But, QA is different than Prod, we can't test for differences"?

The IaC code, that was tested, should be the same in QA as it is in Prod. We should be able to roll back at a moments notice. 
The Space values help us define those slight differences. 

You might be asking "Why are the Space values iterated/put/inserted with boto3 and not with native AWS CDK Classes?"
Well, at the time of writing we could not find a safe/efficient way of getting these values into AWS Parameter Store and AWS Secrets Manager in 
an easy/efficient/safe way without exposing the values in a Cloud Formation Stack. 

*We are admitting defeat here* 

*We are not ashamed*

If we were to define a "Space" as an environment that exists in different VPCs or some other different value that is necessary for 
separation between our environments, then, this project is merely a jumping off point to do that. It is merely an example of how to do it a different way. 
It is not "the way". 

### **AwsHostingCDKPipeline(SPACE)Stack**

In order to understand this stack we must understand "the why and the how" first. This stacks main purpose is to deploy the CDK Pipelines of the Spaces found
in the "space_list" parameter built in the last stack. Let's look at the code that is used with the "Space" data to build each CDK Pipeline. 

```python
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
```

Notice the pipeline_name, the authentication, the repo, the branch, the commands, even the policy. All of these values are stored in either AWS Parameter Store or AWS Secrets Manager. Each space contains it's value for each of these when we input this data into AWS Secrets Manager as the "state-json" secret. If we were to add a value, something that is clearly a different value in QA then Prod, we would expand our JSON string in Secrets Manager and adjust accordingly. Even adding another Space, would be easy. Say, a new feature branch that deploys to a new domain. This is just a bunch of examples of how to do many things. All in one project.  

```json
    "code_build_step_commands":["npm install -g aws-cdk", 
        "python -m pip install -r requirements.txt",
        "cdk deploy AwsHostingThepolymathmanQaStack --context space=qa --require-approval never"
        ],
```

Above are the commands that are passed into the CDK Pipeline. Once this is deployed, the CDK Pipeline only runs when a commit happens on it's respective branch that it is listening on. It only runs against the Application Stack "AwsHostingThepolymathmanQaStack". This ensures that we can continuously develop on the Application stack. Commit to QA. Test. The changes are deployed for us. When the IAC changes in QA are thoroughly tested and working, we then change the Prod stack to be the same. We commit all this code to the QA Branch and then merge all the QA code into Main. Since the CDK Pipeline for Prod is listening for changes on Main it will deploy the new changes. As this project grows we will add approvals for these Pipelines going into the Prod site. New journal posts will be added as we create new automation for these sites.  


If we ever need to update the IAM policy or actual commands (for the CDK Pipeline) in the CodeBuildStep command parameter we would update the string in state.json for the commands or IAM policy and then we run the following command:

"cdk deploy AwsHostingCDKPipelineQaStack --context space=qa --require-approval never"

We would then follow suit in Prod if the QA testing on this passes. 

The magic? Once everything is working with the pipeline and rights to create/build/access the services needed for your app, then its just a matter of updating application code stack, doing commits, letting the pipeline update for you and keep building.

Keep adding to your app now. The infrastructure is self-deployed in the application stack. With gates (future journal posts) 
It's just a matter of making commits to that stack. This is what we view the meaning of the term GitOps might be. It is also a form of NoOps. Bottom line, it works for us.