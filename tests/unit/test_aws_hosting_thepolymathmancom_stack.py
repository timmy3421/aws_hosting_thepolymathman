import aws_cdk as core
import aws_cdk.assertions as assertions

from aws_hosting_thepolymathman.aws_hosting_thepolymathman_stack import AwsHostingThepolymathmancomStack

# example tests. To run these tests, uncomment this file along with the example
# resource in aws_hosting_thepolymathmancom/aws_hosting_thepolymathmancom_stack.py
def test_sqs_queue_created():
    app = core.App()
    stack = AwsHostingThepolymathmancomStack(app, "aws-hosting-thepolymathmancom")
    template = assertions.Template.from_stack(stack)

#     template.has_resource_properties("AWS::SQS::Queue", {
#         "VisibilityTimeout": 300
#     })
