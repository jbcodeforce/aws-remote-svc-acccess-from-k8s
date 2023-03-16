from aws_cdk import (
    # Duration,
    Stack,
    aws_iam as iam,
    SecretValue,
    aws_ecr as ecr

    # aws_sqs as sqs,
)
from constructs import Construct

class CdkStack(Stack):

    def __init__(self, scope: Construct, construct_id: str, **kwargs) -> None:
        super().__init__(scope, construct_id, **kwargs)
        policy = iam.Policy(self,"ecr-auth-token-policy",
                statements= [
                    iam.PolicyStatement(
                        actions= ["ecr:GetAuthorizationToken"],
                        resources=["*"]
                    )
                ]
        )
        user = iam.User(self,
                        "ecruser",
                        password=SecretValue.unsafe_plain_text("T0ch@ngefordemo"))
        user.attach_inline_policy(policy);

        # create ECR repository
        repository=ecr.Repository.from_repository_name(self, 
                                                       "demoRepository",  
                                                       repository_name="jbcodeforce/s3bucketlist")
