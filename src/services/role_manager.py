"""
Role Manager Service for AWS Role Request System
Handles IAM Role and Policy creation/deletion
"""
import os
import json
import boto3
from datetime import datetime, timezone, timedelta
from typing import Dict, Any, Optional, List

from models import RoleRequest

# Korea Standard Time (UTC+9)
KST = timezone(timedelta(hours=9))


# Service-specific permissions for Console access
SERVICE_PERMISSIONS = {
    "ec2": {
        "read": [
            "ec2:Describe*",
            "ec2:Get*",
            "elasticloadbalancing:Describe*",
            "autoscaling:Describe*",
            "cloudwatch:Describe*",
            "cloudwatch:Get*",
            "cloudwatch:List*",
            # SSM Session Manager - Read permissions
            "ssm:DescribeSessions",
            "ssm:GetConnectionStatus",
            "ssm:DescribeInstanceInformation",
            "ssm:DescribeInstanceProperties",
            # EC2 Instance Profile - Read permissions
            "iam:ListInstanceProfiles",
            "iam:GetInstanceProfile",
            "ec2:DescribeIamInstanceProfileAssociations",
        ],
        "update": [
            "ec2:StartInstances",
            "ec2:StopInstances",
            "ec2:RebootInstances",
            "ec2:ModifyInstanceAttribute",
            "ec2:ModifyVolume*",
            "ec2:CreateTags",
            "ec2:DeleteTags",
            # EC2 Instance Profile - Update permissions
            "ec2:AssociateIamInstanceProfile",
            "ec2:ReplaceIamInstanceProfileAssociation",
            # EC2 Instance Connect
            "ec2-instance-connect:SendSSHPublicKey",
            "ec2-instance-connect:SendSerialConsoleSSHPublicKey",
            # SSM Session Manager - Session control (tag-based)
            "ssm:StartSession",
            "ssm:TerminateSession",
            "ssm:ResumeSession",
            "ssmmessages:CreateControlChannel",
            "ssmmessages:CreateDataChannel",
            "ssmmessages:OpenControlChannel",
            "ssmmessages:OpenDataChannel",
            "ec2messages:AcknowledgeMessage",
            "ec2messages:DeleteMessage",
            "ec2messages:FailMessage",
            "ec2messages:GetEndpoint",
            "ec2messages:GetMessages",
            "ec2messages:SendReply",
            # Security Group 규칙 수정 (기존 SG에 규칙 추가/제거)
            "ec2:AuthorizeSecurityGroupIngress",
            "ec2:AuthorizeSecurityGroupEgress",
            "ec2:RevokeSecurityGroupIngress",
            "ec2:RevokeSecurityGroupEgress",
        ],
        "create": [
            "ec2:RunInstances",
            "ec2:CreateVolume",
            "ec2:CreateSnapshot",
            "ec2:CreateImage",
            "ec2:CreateSecurityGroup",
            "ec2:CreateKeyPair",
            "ec2:ImportKeyPair",
            "ec2:AllocateAddress",
            "ec2:AssociateAddress",
        ],
        "delete": [
            "ec2:TerminateInstances",
            "ec2:DeleteVolume",
            "ec2:DeleteSnapshot",
            "ec2:DeregisterImage",
            "ec2:DeleteSecurityGroup",
            "ec2:DeleteKeyPair",
            "ec2:ReleaseAddress",
            "ec2:DisassociateAddress",
            # EC2 Instance Profile - Delete permissions
            "ec2:DisassociateIamInstanceProfile",
        ],
    },
    "rds": {
        "read": [
            "rds:Describe*",
            "rds:List*",
            "rds:Download*",
            "cloudwatch:Describe*",
            "cloudwatch:Get*",
            "cloudwatch:List*",
            "logs:Describe*",
            "logs:Get*",
            "logs:FilterLogEvents",
        ],
        "update": [
            "rds:ModifyDBInstance",
            "rds:ModifyDBCluster",
            "rds:ModifyDBParameterGroup",
            "rds:RebootDBInstance",
            "rds:StartDBInstance",
            "rds:StopDBInstance",
            "rds:AddTagsToResource",
            "rds:RemoveTagsFromResource",
        ],
        "create": [
            "rds:CreateDBInstance",
            "rds:CreateDBCluster",
            "rds:CreateDBSnapshot",
            "rds:CreateDBClusterSnapshot",
            "rds:CreateDBParameterGroup",
            "rds:CreateDBSubnetGroup",
            "rds:RestoreDBInstanceFromDBSnapshot",
        ],
        "delete": [
            "rds:DeleteDBInstance",
            "rds:DeleteDBCluster",
            "rds:DeleteDBSnapshot",
            "rds:DeleteDBClusterSnapshot",
            "rds:DeleteDBParameterGroup",
            "rds:DeleteDBSubnetGroup",
        ],
    },
    "lambda": {
        "read": [
            "lambda:Get*",
            "lambda:List*",
            "logs:Describe*",
            "logs:Get*",
            "logs:FilterLogEvents",
            "logs:StartQuery",
            "logs:StopQuery",
            "logs:GetQueryResults",
            "cloudwatch:Describe*",
            "cloudwatch:Get*",
            "cloudwatch:List*",
        ],
        "update": [
            "lambda:UpdateFunctionCode",
            "lambda:UpdateFunctionConfiguration",
            "lambda:UpdateAlias",
            "lambda:PublishVersion",
            "lambda:TagResource",
            "lambda:UntagResource",
            "lambda:PutFunctionConcurrency",
            "lambda:PutFunctionEventInvokeConfig",
        ],
        "create": [
            "lambda:CreateFunction",
            "lambda:CreateAlias",
            "lambda:CreateEventSourceMapping",
            "lambda:AddPermission",
            "iam:PassRole",
            "iam:GetRole",
            "iam:ListRoles",
        ],
        "delete": [
            "lambda:DeleteFunction",
            "lambda:DeleteAlias",
            "lambda:DeleteEventSourceMapping",
            "lambda:RemovePermission",
            "lambda:DeleteFunctionConcurrency",
            "lambda:DeleteFunctionEventInvokeConfig",
        ],
    },
    "s3": {
        "read": [
            "s3:GetBucket*",
            "s3:GetObject*",
            "s3:GetEncryptionConfiguration",
            "s3:GetLifecycleConfiguration",
            "s3:ListBucket",
            "s3:ListAllMyBuckets",
            "s3:ListBucketVersions",
            "s3:GetBucketLocation",
        ],
        "update": [
            "s3:PutObject",
            "s3:PutObjectAcl",
            "s3:PutBucketTagging",
            "s3:PutObjectTagging",
            "s3:PutBucketVersioning",
            "s3:PutLifecycleConfiguration",
            "s3:PutEncryptionConfiguration",
        ],
        "create": [
            "s3:CreateBucket",
            "s3:PutBucketPolicy",
            "s3:PutBucketCORS",
            "s3:PutBucketWebsite",
            "s3:PutBucketNotification",
        ],
        "delete": [
            "s3:DeleteObject",
            "s3:DeleteObjectVersion",
            "s3:DeleteBucket",
            "s3:DeleteBucketPolicy",
            "s3:DeleteBucketWebsite",
        ],
    },
    "elasticbeanstalk": {
        "read": [
            "elasticbeanstalk:Describe*",
            "elasticbeanstalk:List*",
            "elasticbeanstalk:Check*",
            "elasticbeanstalk:RequestEnvironmentInfo",
            "elasticbeanstalk:RetrieveEnvironmentInfo",
            "elasticbeanstalk:ValidateConfigurationSettings",
            "cloudformation:Describe*",
            "cloudformation:List*",
            "cloudformation:GetTemplate",
            "autoscaling:Describe*",
            "elasticloadbalancing:Describe*",
            "cloudwatch:Describe*",
            "cloudwatch:Get*",
            "cloudwatch:List*",
            "s3:GetBucket*",
            "s3:GetObject*",
            "s3:ListBucket",
            "sns:List*",
            "sqs:List*",
            # EC2 읽기 (EB 인스턴스 모니터링)
            "ec2:Describe*",
            "ec2:Get*",
            # SSM 읽기 (세션 관리자)
            "ssm:DescribeSessions",
            "ssm:GetConnectionStatus",
            "ssm:DescribeInstanceInformation",
            "ssm:DescribeInstanceProperties",
            # CloudWatch Logs (EB 로그)
            "logs:Describe*",
            "logs:Get*",
            "logs:FilterLogEvents",
            "logs:StartQuery",
            "logs:StopQuery",
            "logs:GetQueryResults",
            # RDS 읽기 (EB에 연결된 RDS 모니터링)
            "rds:Describe*",
            "rds:List*",
        ],
        "update": [
            "elasticbeanstalk:UpdateEnvironment",
            "elasticbeanstalk:UpdateApplication",
            "elasticbeanstalk:UpdateApplicationVersion",
            "elasticbeanstalk:UpdateConfigurationTemplate",
            "elasticbeanstalk:RestartAppServer",
            "elasticbeanstalk:RebuildEnvironment",
            "elasticbeanstalk:SwapEnvironmentCNAMEs",
            "elasticbeanstalk:UpdateTagsForResource",
            "elasticbeanstalk:AddTags",
            "elasticbeanstalk:RemoveTags",
            # EC2 인스턴스 관리
            "ec2:StartInstances",
            "ec2:StopInstances",
            "ec2:RebootInstances",
            "ec2:ModifyInstanceAttribute",
            "ec2:CreateTags",
            "ec2:DeleteTags",
            # EC2 Instance Connect
            "ec2-instance-connect:SendSSHPublicKey",
            "ec2-instance-connect:SendSerialConsoleSSHPublicKey",
            # SSM Session Manager
            "ssm:StartSession",
            "ssm:TerminateSession",
            "ssm:ResumeSession",
            "ssmmessages:CreateControlChannel",
            "ssmmessages:CreateDataChannel",
            "ssmmessages:OpenControlChannel",
            "ssmmessages:OpenDataChannel",
            "ec2messages:AcknowledgeMessage",
            "ec2messages:DeleteMessage",
            "ec2messages:FailMessage",
            "ec2messages:GetEndpoint",
            "ec2messages:GetMessages",
            "ec2messages:SendReply",
            # AutoScaling 관리
            "autoscaling:UpdateAutoScalingGroup",
            "autoscaling:SetDesiredCapacity",
            "autoscaling:SuspendProcesses",
            "autoscaling:ResumeProcesses",
            "autoscaling:CreateOrUpdateTags",
            "autoscaling:DeleteTags",
            # CloudFormation 관리
            "cloudformation:UpdateStack",
            "cloudformation:CancelUpdateStack",
            "cloudformation:ContinueUpdateRollback",
            "cloudformation:SignalResource",
            "cloudformation:TagResource",
            "cloudformation:UntagResource",
            # S3 (EB 배포용)
            "s3:PutObject",
            "s3:DeleteObject",
            # ELB (EB 로드밸런서 관리)
            "elasticloadbalancing:ModifyLoadBalancerAttributes",
            "elasticloadbalancing:ModifyTargetGroupAttributes",
            "elasticloadbalancing:ModifyListener",
            "elasticloadbalancing:ModifyRule",
            "elasticloadbalancing:SetSecurityGroups",
            "elasticloadbalancing:SetSubnets",
            "elasticloadbalancing:AddTags",
            "elasticloadbalancing:RemoveTags",
            "elasticloadbalancing:RegisterTargets",
            "elasticloadbalancing:DeregisterTargets",
        ],
        "create": [
            "elasticbeanstalk:CreateApplication",
            "elasticbeanstalk:CreateApplicationVersion",
            "elasticbeanstalk:CreateEnvironment",
            "elasticbeanstalk:CreateConfigurationTemplate",
            "elasticbeanstalk:CreateStorageLocation",
            "s3:PutObject",
            "s3:CreateBucket",
            # CloudFormation (EB 환경 생성 시 필요)
            "cloudformation:CreateStack",
            "cloudformation:CreateChangeSet",
            "cloudformation:ExecuteChangeSet",
            # AutoScaling
            "autoscaling:CreateAutoScalingGroup",
            "autoscaling:CreateLaunchConfiguration",
            # ELB (EB 환경 생성 시 필요)
            "elasticloadbalancing:CreateLoadBalancer",
            "elasticloadbalancing:CreateTargetGroup",
            "elasticloadbalancing:CreateListener",
            "elasticloadbalancing:CreateRule",
        ],
        "delete": [
            "elasticbeanstalk:DeleteApplication",
            "elasticbeanstalk:DeleteApplicationVersion",
            "elasticbeanstalk:DeleteEnvironmentConfiguration",
            "elasticbeanstalk:DeleteConfigurationTemplate",
            "elasticbeanstalk:TerminateEnvironment",
            # CloudFormation
            "cloudformation:DeleteStack",
            "cloudformation:DeleteChangeSet",
            # AutoScaling
            "autoscaling:DeleteAutoScalingGroup",
            "autoscaling:DeleteLaunchConfiguration",
            # ELB
            "elasticloadbalancing:DeleteLoadBalancer",
            "elasticloadbalancing:DeleteTargetGroup",
            "elasticloadbalancing:DeleteListener",
            "elasticloadbalancing:DeleteRule",
        ],
    },
    "dynamodb": {
        "read": [
            "dynamodb:DescribeTable",
            "dynamodb:DescribeStream",
            "dynamodb:DescribeTimeToLive",
            "dynamodb:DescribeContinuousBackups",
            "dynamodb:DescribeBackup",
            "dynamodb:ListTables",
            "dynamodb:ListBackups",
            "dynamodb:ListStreams",
            "dynamodb:ListTagsOfResource",
            "dynamodb:GetItem",
            "dynamodb:BatchGetItem",
            "dynamodb:Query",
            "dynamodb:Scan",
            "cloudwatch:Describe*",
            "cloudwatch:Get*",
            "cloudwatch:List*",
        ],
        "update": [
            "dynamodb:PutItem",
            "dynamodb:UpdateItem",
            "dynamodb:DeleteItem",
            "dynamodb:BatchWriteItem",
            "dynamodb:UpdateTable",
            "dynamodb:UpdateTimeToLive",
            "dynamodb:UpdateContinuousBackups",
            "dynamodb:TagResource",
            "dynamodb:UntagResource",
        ],
        "create": [
            "dynamodb:CreateTable",
            "dynamodb:CreateBackup",
            "dynamodb:CreateGlobalTable",
            "dynamodb:RestoreTableFromBackup",
            "dynamodb:RestoreTableToPointInTime",
        ],
        "delete": [
            "dynamodb:DeleteTable",
            "dynamodb:DeleteBackup",
        ],
    },
    "elasticloadbalancing": {
        "read": [
            "elasticloadbalancing:Describe*",
            "cloudwatch:Describe*",
            "cloudwatch:Get*",
            "cloudwatch:List*",
            # ACM 인증서 조회 (ELB에 인증서 연결 시 필요)
            "acm:ListCertificates",
            "acm:DescribeCertificate",
            "acm:GetCertificate",
        ],
        "update": [
            "elasticloadbalancing:ModifyLoadBalancerAttributes",
            "elasticloadbalancing:ModifyTargetGroupAttributes",
            "elasticloadbalancing:ModifyListener",
            "elasticloadbalancing:ModifyRule",
            "elasticloadbalancing:SetSecurityGroups",
            "elasticloadbalancing:SetSubnets",
            "elasticloadbalancing:AddTags",
            "elasticloadbalancing:RemoveTags",
            "elasticloadbalancing:RegisterTargets",
            "elasticloadbalancing:DeregisterTargets",
            "elasticloadbalancing:AddListenerCertificates",
            "elasticloadbalancing:RemoveListenerCertificates",
        ],
        "create": [
            "elasticloadbalancing:CreateLoadBalancer",
            "elasticloadbalancing:CreateTargetGroup",
            "elasticloadbalancing:CreateListener",
            "elasticloadbalancing:CreateRule",
        ],
        "delete": [
            "elasticloadbalancing:DeleteLoadBalancer",
            "elasticloadbalancing:DeleteTargetGroup",
            "elasticloadbalancing:DeleteListener",
            "elasticloadbalancing:DeleteRule",
        ],
    },
    "route53": {
        "read": [
            "route53:Get*",
            "route53:List*",
            "route53:TestDNSAnswer",
            "route53:GetHostedZoneCount",
            "route53:GetHostedZoneLimit",
            "route53:GetAccountLimit",
            "route53:GetDNSSEC",
            "route53:GetQueryLoggingConfig",
            "route53domains:Get*",
            "route53domains:List*",
        ],
        "update": [
            "route53:ChangeResourceRecordSets",
            "route53:ChangeTagsForResource",
            "route53:AssociateVPCWithHostedZone",
            "route53:DisassociateVPCFromHostedZone",
        ],
        "create": [
            "route53:CreateHostedZone",
            "route53:CreateHealthCheck",
        ],
        "delete": [
            "route53:DeleteHostedZone",
            "route53:DeleteHealthCheck",
        ],
    },
    "amplify": {
        "read": [
            "amplify:Get*",
            "amplify:List*",
        ],
        "update": [
            "amplify:UpdateApp",
            "amplify:UpdateBranch",
            "amplify:UpdateDomainAssociation",
            "amplify:StartDeployment",
            "amplify:StopDeployment",
            "amplify:StartJob",
            "amplify:StopJob",
        ],
        "create": [
            "amplify:CreateApp",
            "amplify:CreateBranch",
            "amplify:CreateDeployment",
            "amplify:CreateDomainAssociation",
        ],
        "delete": [
            "amplify:DeleteApp",
            "amplify:DeleteBranch",
            "amplify:DeleteDomainAssociation",
            "amplify:DeleteJob",
        ],
    },
    "billing": {
        "read": [
            "ce:Get*",
            "ce:Describe*",
            "ce:List*",
            "pricing:GetProducts",
            "pricing:DescribeServices",
            "pricing:GetAttributeValues",
            "budgets:ViewBudget",
            "budgets:Describe*",
            "cur:DescribeReportDefinitions",
        ],
    },
    "ecr": {
        "read": [
            "ecr:Describe*", "ecr:Get*", "ecr:List*",
            "ecr:BatchGetImage", "ecr:BatchCheckLayerAvailability",
        ],
        "update": [
            "ecr:PutImage", "ecr:InitiateLayerUpload", "ecr:UploadLayerPart",
            "ecr:CompleteLayerUpload", "ecr:BatchDeleteImage",
            "ecr:TagResource", "ecr:UntagResource",
            "ecr:PutImageTagMutability", "ecr:PutImageScanningConfiguration",
            "ecr:PutLifecyclePolicy", "ecr:StartLifecyclePolicyPreview",
            "ecr:SetRepositoryPolicy",
        ],
        "create": [
            "ecr:CreateRepository", "ecr:CreatePullThroughCacheRule",
        ],
        "delete": [
            "ecr:DeleteRepository", "ecr:DeleteRepositoryPolicy",
            "ecr:DeleteLifecyclePolicy", "ecr:DeletePullThroughCacheRule",
        ],
    },
    "eks": {
        "read": [
            "eks:DescribeCluster",
            "eks:DescribeNodegroup",
            "eks:DescribeAddon",
            "eks:DescribeFargateProfile",
            "eks:DescribeUpdate",
            "eks:DescribeAccessEntry",
            "eks:ListClusters",
            "eks:ListNodegroups",
            "eks:ListAddons",
            "eks:ListFargateProfiles",
            "eks:ListUpdates",
            "eks:ListAccessEntries",
            "eks:ListAccessPolicies",
            "eks:AccessKubernetesApi",
            # EKS 클러스터 생성/관리에 필요한 EC2 네트워크 읽기 권한
            "ec2:DescribeSubnets",
            "ec2:DescribeVpcs",
            "ec2:DescribeSecurityGroups",
            "ec2:DescribeSecurityGroupRules",
            "ec2:DescribeRouteTables",
            "ec2:DescribeInternetGateways",
            "ec2:DescribeNatGateways",
            # CloudWatch/Logs
            "cloudwatch:Describe*",
            "cloudwatch:Get*",
            "cloudwatch:List*",
            "logs:DescribeLogGroups",
            "logs:GetLogEvents",
            "logs:FilterLogEvents",
        ],
        "update": [
            "eks:UpdateClusterConfig",
            "eks:UpdateNodegroupConfig",
            "eks:UpdateClusterVersion",
            "eks:UpdateAddon",
            "eks:TagResource",
            "eks:UntagResource",
            "eks:AssociateAccessPolicy",
            "eks:DisassociateAccessPolicy",
            "eks:UpdateAccessEntry",
        ],
        "create": [
            "eks:CreateCluster",
            "eks:CreateNodegroup",
            "eks:CreateAddon",
            "eks:CreateFargateProfile",
            "eks:CreateAccessEntry",
            "iam:CreateServiceLinkedRole",
            # EKS 클러스터용 Security Group 생성
            "ec2:CreateSecurityGroup",
            "ec2:AuthorizeSecurityGroupIngress",
            "ec2:AuthorizeSecurityGroupEgress",
            "ec2:CreateTags",
        ],
        "delete": [
            "eks:DeleteCluster",
            "eks:DeleteNodegroup",
            "eks:DeleteAddon",
            "eks:DeleteFargateProfile",
            "eks:DeleteAccessEntry",
        ],
    },
    "bedrock": {
        "read": [
            # 모델 카탈로그 조회
            "bedrock:ListFoundationModels", "bedrock:GetFoundationModel",
            "bedrock:ListCustomModels", "bedrock:GetCustomModel",
            # Agent / KB / Guardrail 조회
            "bedrock:ListAgents", "bedrock:GetAgent",
            "bedrock:ListAgentAliases", "bedrock:GetAgentAlias",
            "bedrock:ListKnowledgeBases", "bedrock:GetKnowledgeBase",
            "bedrock:ListDataSources", "bedrock:GetDataSource",
            "bedrock:ListGuardrails", "bedrock:GetGuardrail",
            "bedrock:ListTagsForResource",
            "bedrock:GetModelInvocationLoggingConfiguration",
            # 모델 호출 (사용량 과금) - InvokeModel은 모델 ARN 기준이라 ResourceTag 적용 불가
            "bedrock:InvokeModel", "bedrock:InvokeModelWithResponseStream",
            "bedrock:Retrieve", "bedrock:RetrieveAndGenerate", "bedrock:InvokeAgent",
            # 모니터링/로그
            "cloudwatch:Describe*", "cloudwatch:Get*", "cloudwatch:List*",
            "logs:DescribeLogGroups", "logs:GetLogEvents", "logs:FilterLogEvents",
            # 연관 서비스 read (KB 데이터 소스 = S3, Action Group = Lambda)
            "s3:GetObject", "s3:GetBucketLocation", "s3:ListBucket",
            "lambda:GetFunction", "lambda:ListFunctions",
        ],
        "update": [
            "bedrock:UpdateAgent", "bedrock:PrepareAgent",
            "bedrock:UpdateAgentAlias",
            "bedrock:UpdateKnowledgeBase", "bedrock:UpdateDataSource",
            "bedrock:UpdateGuardrail",
            "bedrock:StartIngestionJob", "bedrock:StopIngestionJob",
            "bedrock:TagResource", "bedrock:UntagResource",
            "bedrock:PutModelInvocationLoggingConfiguration",
        ],
        "create": [
            "bedrock:CreateAgent", "bedrock:CreateAgentAlias",
            "bedrock:CreateKnowledgeBase", "bedrock:CreateDataSource",
            "bedrock:CreateGuardrail", "bedrock:CreateGuardrailVersion",
            "iam:CreateServiceLinkedRole",
        ],
        "delete": [
            "bedrock:DeleteAgent", "bedrock:DeleteAgentAlias",
            "bedrock:DeleteKnowledgeBase", "bedrock:DeleteDataSource",
            "bedrock:DeleteGuardrail",
            "bedrock:DeleteCustomModel",
            # 고비용 액션 - delete 카테고리에 두어 full에서만 부여됨
            "bedrock:CreateModelCustomizationJob",
            "bedrock:CreateProvisionedModelThroughput",
            "bedrock:DeleteProvisionedModelThroughput",
        ],
    },
}


class RoleManager:
    """Manages IAM Role creation and deletion"""
    
    def __init__(
        self,
        iam_client=None,
        account_id: Optional[str] = None,
        company_ip_range: Optional[str] = None,
        bastion_instance_id: Optional[str] = None,
        bastion_region: Optional[str] = None,
    ):
        self.iam_client = iam_client or boto3.client("iam")
        self.account_id = account_id or boto3.client("sts").get_caller_identity()["Account"]
        self.company_ip_range = company_ip_range or "0.0.0.0/0"
        # Bastion: SSH 차단 정책에 따라 모든 role에 SSM 접근 기본 부여
        self.bastion_instance_id = bastion_instance_id or os.environ.get(
            "BASTION_INSTANCE_ID", "i-01af38d47bfa846a6"
        )
        self.bastion_region = bastion_region or os.environ.get(
            "BASTION_REGION", "ap-northeast-2"
        )
    
    def generate_role_name(self, request: RoleRequest) -> str:
        """
        Generate unique role name
        
        Args:
            request: Role request
        
        Returns:
            Unique role name
        """
        import uuid
        unique_id = str(uuid.uuid4())[:8]
        timestamp = datetime.now(KST).strftime("%Y%m%d%H%M%S")
        return f"dynamic-role-{request.iam_user_name}-{request.env}-{request.service}-{timestamp}-{unique_id}"
    
    def create_dynamic_role(self, request: RoleRequest) -> Dict[str, Any]:
        """
        Create dynamic IAM role with policy
        
        Args:
            request: Role request
        
        Returns:
            Dict with role_arn and policy_arn
        """
        role_name = self.generate_role_name(request)
        policy_name = f"{role_name}-policy"
        
        print(f"[RoleManager] Creating role: {role_name}")
        print(f"[RoleManager] Request: user={request.iam_user_name}, env={request.env}, service={request.service}")
        
        # Create trust policy
        trust_policy = self._generate_trust_policy(request)
        print(f"[RoleManager] Trust policy created")
        
        # Create role (description must be ASCII only)
        description = f"Dynamic role for {request.iam_user_name} - Env:{request.env} Service:{request.service}"

        # MaxSessionDuration: 요청 기간만큼 설정 (최소 3600초, 최대 43200초=12시간)
        duration_seconds = int((request.end_time - request.start_time).total_seconds())
        max_session_duration = max(3600, min(duration_seconds, 43200))
        print(f"[RoleManager] MaxSessionDuration: {max_session_duration}s ({max_session_duration // 3600}h {(max_session_duration % 3600) // 60}m)")

        role_response = self.iam_client.create_role(
            RoleName=role_name,
            AssumeRolePolicyDocument=json.dumps(trust_policy),
            Description=description,
            MaxSessionDuration=max_session_duration,
            Tags=[
                {"Key": "RequestId", "Value": request.request_id},
                {"Key": "Requester", "Value": request.iam_user_name},
                {"Key": "Env", "Value": request.env},
                {"Key": "Service", "Value": request.service},
                {"Key": "Owner", "Value": "N1104365"},
            ],
        )
        role_arn = role_response["Role"]["Arn"]
        print(f"[RoleManager] Role created: {role_arn}")
        
        # Create permission policy
        # Inline policy limit: 10,240 bytes TOTAL for all inline policies on a role
        # Managed policy limit: 6,144 bytes per policy, up to 10 per role
        permission_policy = self._generate_permission_policy(request)
        policy_json = json.dumps(permission_policy)
        print(f"[RoleManager] Policy size: {len(policy_json)} bytes")

        MAX_INLINE_SIZE = 10240
        MAX_MANAGED_SIZE = 6144

        if len(policy_json) <= MAX_INLINE_SIZE:
            # Fits in a single inline policy
            inline_name = f"{role_name}-policy"
            self.iam_client.put_role_policy(
                RoleName=role_name,
                PolicyName=inline_name,
                PolicyDocument=policy_json,
            )
            print(f"[RoleManager] Inline policy attached: {inline_name}")
            return {
                "role_arn": role_arn,
                "policy_arn": inline_name,
                "role_name": role_name,
                "max_session_duration": max_session_duration,
            }
        else:
            # Too large for inline → split into managed policies (6,144 bytes each)
            print(f"[RoleManager] Policy exceeds inline limit ({MAX_INLINE_SIZE}), using managed policies")
            policy_parts = self._split_policy(permission_policy, role_name, MAX_MANAGED_SIZE)
            print(f"[RoleManager] Split into {len(policy_parts)} managed policies")

            managed_arns = []
            for part_name, part_json in policy_parts:
                print(f"[RoleManager] Creating managed policy: {part_name} ({len(part_json)} bytes)")
                create_resp = self.iam_client.create_policy(
                    PolicyName=part_name,
                    PolicyDocument=part_json,
                    Description=f"Dynamic policy for {request.iam_user_name}",
                )
                policy_arn = create_resp["Policy"]["Arn"]
                managed_arns.append(policy_arn)

                self.iam_client.attach_role_policy(
                    RoleName=role_name,
                    PolicyArn=policy_arn,
                )
                print(f"[RoleManager] Attached managed policy: {policy_arn}")

            return {
                "role_arn": role_arn,
                "policy_arn": ",".join(managed_arns),
                "role_name": role_name,
                "max_session_duration": max_session_duration,
            }

    def delete_dynamic_role(self, role_arn: str, policy_arn: str) -> None:
        """
        Delete dynamic role and all attached policies (inline + managed).

        Args:
            role_arn: Role ARN to delete
            policy_arn: Comma-separated policy ARNs or inline policy name(s)
        """
        role_name = role_arn.split("/")[-1]
        print(f"[RoleManager] Deleting role: {role_name}")

        # 1. Delete all inline policies
        try:
            response = self.iam_client.list_role_policies(RoleName=role_name)
            for inline_name in response.get('PolicyNames', []):
                try:
                    self.iam_client.delete_role_policy(
                        RoleName=role_name, PolicyName=inline_name,
                    )
                    print(f"[RoleManager] Deleted inline policy: {inline_name}")
                except self.iam_client.exceptions.NoSuchEntityException:
                    pass
        except self.iam_client.exceptions.NoSuchEntityException:
            pass

        # 2. Detach and delete all managed policies
        try:
            response = self.iam_client.list_attached_role_policies(RoleName=role_name)
            for attached in response.get('AttachedPolicies', []):
                p_arn = attached['PolicyArn']
                try:
                    self.iam_client.detach_role_policy(
                        RoleName=role_name, PolicyArn=p_arn,
                    )
                    print(f"[RoleManager] Detached managed policy: {p_arn}")
                except self.iam_client.exceptions.NoSuchEntityException:
                    pass

                # Delete managed policy (remove non-default versions first)
                try:
                    versions = self.iam_client.list_policy_versions(PolicyArn=p_arn)
                    for version in versions.get('Versions', []):
                        if not version['IsDefaultVersion']:
                            self.iam_client.delete_policy_version(
                                PolicyArn=p_arn, VersionId=version['VersionId'],
                            )
                    self.iam_client.delete_policy(PolicyArn=p_arn)
                    print(f"[RoleManager] Deleted managed policy: {p_arn}")
                except self.iam_client.exceptions.NoSuchEntityException:
                    pass
        except self.iam_client.exceptions.NoSuchEntityException:
            pass

        # 3. Delete the role
        try:
            self.iam_client.delete_role(RoleName=role_name)
            print(f"[RoleManager] Deleted role: {role_name}")
        except self.iam_client.exceptions.NoSuchEntityException:
            pass
    
    def _split_policy(
        self,
        policy: Dict[str, Any],
        role_name: str,
        max_size: int,
    ) -> List[tuple]:
        """
        Split policy into multiple parts, each under max_size bytes.

        Returns:
            List of (policy_name, policy_json_str) tuples
        """
        statements = policy["Statement"]
        policies = []
        current_statements = []
        policy_index = 1

        for stmt in statements:
            test_policy = {
                "Version": "2012-10-17",
                "Statement": current_statements + [stmt],
            }
            test_json = json.dumps(test_policy)

            if len(test_json) > max_size and current_statements:
                flush_policy = {
                    "Version": "2012-10-17",
                    "Statement": current_statements,
                }
                policies.append((
                    f"{role_name}-policy-{policy_index}",
                    json.dumps(flush_policy),
                ))
                policy_index += 1
                current_statements = [stmt]
            else:
                current_statements.append(stmt)

        if current_statements:
            flush_policy = {
                "Version": "2012-10-17",
                "Statement": current_statements,
            }
            policies.append((
                f"{role_name}-policy-{policy_index}",
                json.dumps(flush_policy),
            ))

        return policies

    def _generate_trust_policy(self, request: RoleRequest) -> Dict[str, Any]:
        """
        Generate trust policy for the role
        
        Args:
            request: Role request
        
        Returns:
            Trust policy document
        """
        return {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {
                        "AWS": f"arn:aws:iam::{self.account_id}:user/{request.iam_user_name}"
                    },
                    "Action": "sts:AssumeRole",
                    "Condition": {
                        "IpAddress": {
                            "aws:SourceIp": self.company_ip_range
                        }
                    }
                }
            ]
        }
    
    def _generate_permission_policy(self, request: RoleRequest) -> Dict[str, Any]:
        """
        Generate permission policy for the role based on permission_type and target_services
        
        Args:
            request: Role request
        
        Returns:
            Permission policy document
        """
        statements = []
        permission_type = getattr(request, 'permission_type', 'read_update')
        target_services = getattr(request, 'target_services', ['all'])
        
        # Determine which services to include
        # 'all'은 일반 서비스만 포함하고, bedrock 같이 'all'에서 의도적으로 제외된 서비스는
        # 사용자가 명시적으로 추가 선택해야만 부여 (비용 통제)
        if 'all' in target_services:
            services_to_include = ['ec2', 'rds', 'lambda', 's3', 'elasticbeanstalk', 'dynamodb', 'elasticloadbalancing', 'route53', 'amplify', 'billing', 'ecr', 'eks']
            # 'all' 외에 명시 선택된 서비스(예: bedrock)도 추가
            for svc in target_services:
                if svc != 'all' and svc in SERVICE_PERMISSIONS and svc not in services_to_include:
                    services_to_include.append(svc)
        else:
            services_to_include = target_services
        
        # Services that don't support tag-based conditions
        NO_TAG_CONDITION_SERVICES = ['route53', 'amplify', 'billing']

        # Collect actions based on permission type
        read_actions = []
        tagged_actions = []
        create_actions = []

        for svc in services_to_include:
            if svc in SERVICE_PERMISSIONS:
                perms = SERVICE_PERMISSIONS[svc]

                # Always include read permissions
                read_actions.extend(perms.get('read', []))

                if svc in NO_TAG_CONDITION_SERVICES:
                    # No tag condition — all actions go to read_actions (unconditioned)
                    if permission_type in ['read_update', 'read_update_create', 'full']:
                        read_actions.extend(perms.get('update', []))
                    if permission_type in ['read_update_create', 'full']:
                        read_actions.extend(perms.get('create', []))
                    if permission_type == 'full':
                        read_actions.extend(perms.get('delete', []))
                else:
                    # Tag-based condition services
                    if permission_type in ['read_update', 'read_update_create', 'full']:
                        tagged_actions.extend(perms.get('update', []))

                    if permission_type in ['read_update_create', 'full']:
                        create_actions.extend(perms.get('create', []))

                    if permission_type == 'full':
                        tagged_actions.extend(perms.get('delete', []))

        # EB 서비스: 태그를 지원하지 않는 배포 액션을 조건 없는 액션에 포함
        if 'elasticbeanstalk' in services_to_include:
            if permission_type in ['read_update', 'read_update_create', 'full']:
                read_actions.extend([
                    "elasticbeanstalk:CreateApplicationVersion",
                    "elasticbeanstalk:CreateStorageLocation",
                ])

        # SSM/EC2 Messages 액션 분리 (조건 없이 허용해야 함 → read_actions에 합침)
        if tagged_actions:
            ssm_message_actions = [a for a in tagged_actions if a.startswith('ssmmessages:') or a.startswith('ec2messages:')]
            if ssm_message_actions:
                read_actions.extend(ssm_message_actions)
                tagged_actions = [a for a in tagged_actions if a not in ssm_message_actions]

        # Statement 1: 조건 없는 액션 (read + SSM messages + EB deploy)
        if read_actions:
            statements.append({
                "Sid": "ReadOnlyAccess",
                "Effect": "Allow",
                "Action": list(set(read_actions)),
                "Resource": "*",
            })

        # Statement 2: Tag-based permissions (update/delete)
        if tagged_actions:
            # Separate SSM session actions for special condition
            ssm_session_actions = [a for a in tagged_actions if a.startswith('ssm:') and 'Session' in a]
            other_tagged_actions = [a for a in tagged_actions if a not in ssm_session_actions]

            # Regular tag-based actions
            if other_tagged_actions:
                statements.append({
                    "Sid": "TagBasedAccess",
                    "Effect": "Allow",
                    "Action": list(set(other_tagged_actions)),
                    "Resource": "*",
                    "Condition": {
                        "StringEquals": {
                            "aws:ResourceTag/Env": request.env,
                            "aws:ResourceTag/Service": request.service,
                        }
                    }
                })

            # SSM Session actions: StartSession은 EC2 인스턴스, TerminateSession/ResumeSession은 세션 리소스
            if ssm_session_actions:
                ssm_start_actions = [a for a in ssm_session_actions if a == 'ssm:StartSession']
                ssm_session_control_actions = [a for a in ssm_session_actions if a in ('ssm:TerminateSession', 'ssm:ResumeSession')]

                # StartSession: EC2 인스턴스 태그 조건
                if ssm_start_actions:
                    statements.append({
                        "Sid": "SSMSessionAccess",
                        "Effect": "Allow",
                        "Action": ssm_start_actions,
                        "Resource": "arn:aws:ec2:*:*:instance/*",
                        "Condition": {
                            "StringEquals": {
                                "ssm:resourceTag/Env": request.env,
                                "ssm:resourceTag/Service": request.service,
                            }
                        }
                    })

                # TerminateSession/ResumeSession: 세션 리소스 (태그 조건 없음)
                if ssm_session_control_actions:
                    statements.append({
                        "Sid": "SSMSessionControl",
                        "Effect": "Allow",
                        "Action": ssm_session_control_actions,
                        "Resource": "arn:aws:ssm:*:*:session/*",
                    })

                # Allow SSM document access for Session Manager
                statements.append({
                    "Sid": "SSMDocumentAccess",
                    "Effect": "Allow",
                    "Action": [
                        "ssm:StartSession"
                    ],
                    "Resource": [
                        "arn:aws:ssm:*:*:document/AWS-StartSSHSession",
                        "arn:aws:ssm:*:*:document/SSM-SessionManagerRunShell"
                    ]
                })

        # ============================================================
        # Bastion SSM Access (모든 role에 기본 포함 - SSH 차단 정책)
        # target_services, permission_type 무관하게 항상 추가
        # ============================================================
        bastion_arn = (
            f"arn:aws:ec2:{self.bastion_region}:{self.account_id}"
            f":instance/{self.bastion_instance_id}"
        )

        # (a) SSM 세션 시작에 필요한 읽기/통신 액션 (리소스 ARN 미지원 → "*")
        statements.append({
            "Sid": "BastionSSMReadAndChannel",
            "Effect": "Allow",
            "Action": [
                "ec2:DescribeInstances",
                "ssm:DescribeSessions",
                "ssm:GetConnectionStatus",
                "ssm:DescribeInstanceInformation",
                "ssm:DescribeInstanceProperties",
                "ssmmessages:CreateControlChannel",
                "ssmmessages:CreateDataChannel",
                "ssmmessages:OpenControlChannel",
                "ssmmessages:OpenDataChannel",
                "ec2messages:AcknowledgeMessage",
                "ec2messages:GetEndpoint",
                "ec2messages:GetMessages",
                "ec2messages:SendReply",
            ],
            "Resource": "*",
        })

        # (b) StartSession — bastion 인스턴스 + 표준 SSM 문서만 허용
        statements.append({
            "Sid": "BastionSSMStartSession",
            "Effect": "Allow",
            "Action": "ssm:StartSession",
            "Resource": [
                bastion_arn,
                "arn:aws:ssm:*:*:document/AWS-StartSSHSession",
                "arn:aws:ssm:*:*:document/SSM-SessionManagerRunShell",
                "arn:aws:ssm:*:*:document/AWS-StartPortForwardingSession",
                "arn:aws:ssm:*:*:document/AWS-StartPortForwardingSessionToRemoteHost",
            ],
        })

        # (c) 세션 종료/재개
        statements.append({
            "Sid": "BastionSSMSessionControl",
            "Effect": "Allow",
            "Action": ["ssm:TerminateSession", "ssm:ResumeSession"],
            "Resource": "arn:aws:ssm:*:*:session/*",
        })

        # Statement 3: Create permissions with tag enforcement (CreateWithTags + AllowCreateTags 합침)
        if create_actions:
            tag_actions = [
                "ec2:CreateTags",
                "rds:AddTagsToResource",
                "lambda:TagResource",
                "s3:PutBucketTagging",
                "s3:PutObjectTagging",
                "dynamodb:TagResource",
                "autoscaling:CreateOrUpdateTags",
                "elasticbeanstalk:AddTags",
                "eks:TagResource",
                "bedrock:TagResource",
            ]
            statements.append({
                "Sid": "CreateWithTags",
                "Effect": "Allow",
                "Action": list(set(create_actions + tag_actions)),
                "Resource": "*",
                "Condition": {
                    "StringEquals": {
                        "aws:RequestTag/Env": request.env,
                        "aws:RequestTag/Service": request.service,
                    }
                }
            })

        # EC2 + read_update 이상일 때 PassRole Statement 추가
        if 'ec2' in services_to_include:
            if permission_type in ['read_update', 'read_update_create', 'full']:
                statements.append({
                    "Sid": "PassRoleForEC2",
                    "Effect": "Allow",
                    "Action": "iam:PassRole",
                    "Resource": "*",
                    "Condition": {"StringEquals": {"iam:PassedToService": "ec2.amazonaws.com"}}
                })

        # EKS + create 이상일 때 PassRole Statement 추가
        if 'eks' in services_to_include:
            if permission_type in ['read_update_create', 'full']:
                statements.append({
                    "Sid": "PassRoleForEKS",
                    "Effect": "Allow",
                    "Action": "iam:PassRole",
                    "Resource": "*",
                    "Condition": {"StringEquals": {"iam:PassedToService": "eks.amazonaws.com"}}
                })

        # Bedrock + create 이상일 때 PassRole Statement (Agent/KB execution role)
        if 'bedrock' in services_to_include:
            if permission_type in ['read_update_create', 'full']:
                statements.append({
                    "Sid": "PassRoleForBedrock",
                    "Effect": "Allow",
                    "Action": "iam:PassRole",
                    "Resource": "*",
                    "Condition": {"StringEquals": {"iam:PassedToService": "bedrock.amazonaws.com"}}
                })

        # Parameter Store 권한 (권한 타입에 따라 범위 결정)
        if getattr(request, 'include_parameter_store', False):
            ps_actions = [
                "ssm:GetParameter", "ssm:GetParameters",
                "ssm:GetParametersByPath", "ssm:DescribeParameters",
            ]
            if permission_type in ['read_update', 'read_update_create', 'full']:
                ps_actions.append("ssm:PutParameter")
                ps_actions.append("ssm:AddTagsToResource")
                ps_actions.append("ssm:RemoveTagsFromResource")
            if permission_type in ['read_update_create', 'full']:
                ps_actions.append("ssm:PutParameter")  # 신규 생성도 PutParameter
            if permission_type == 'full':
                ps_actions.append("ssm:DeleteParameter")
                ps_actions.append("ssm:DeleteParameters")
            statements.append({
                "Sid": "ParameterStoreAccess",
                "Effect": "Allow",
                "Action": list(set(ps_actions)),
                "Resource": "*",
            })

        # Secrets Manager 권한 (권한 타입에 따라 범위 결정)
        if getattr(request, 'include_secrets_manager', False):
            sm_actions = [
                "secretsmanager:GetSecretValue", "secretsmanager:DescribeSecret",
                "secretsmanager:ListSecrets", "secretsmanager:ListSecretVersionIds",
            ]
            if permission_type in ['read_update', 'read_update_create', 'full']:
                sm_actions.append("secretsmanager:PutSecretValue")
                sm_actions.append("secretsmanager:UpdateSecret")
                sm_actions.append("secretsmanager:TagResource")
                sm_actions.append("secretsmanager:UntagResource")
            if permission_type in ['read_update_create', 'full']:
                sm_actions.append("secretsmanager:CreateSecret")
            if permission_type == 'full':
                sm_actions.append("secretsmanager:DeleteSecret")
            statements.append({
                "Sid": "SecretsManagerAccess",
                "Effect": "Allow",
                "Action": list(set(sm_actions)),
                "Resource": "*",
            })

        # EB 서비스 포함 시, EB S3 Storage 버킷 전용 액세스 추가
        if 'elasticbeanstalk' in services_to_include:
            statements.append({
                "Sid": "EBStorageBucketAccess",
                "Effect": "Allow",
                "Action": [
                    "s3:GetObject",
                    "s3:PutObject",
                    "s3:DeleteObject",
                    "s3:GetBucketLocation",
                    "s3:ListBucket",
                    "s3:ListBucketMultipartUploads",
                    "s3:AbortMultipartUpload",
                    "s3:ListMultipartUploadParts",
                    "s3:PutObjectAcl",
                    "s3:GetObjectAcl",
                ],
                "Resource": [
                    f"arn:aws:s3:::elasticbeanstalk-ap-northeast-2-{self.account_id}",
                    f"arn:aws:s3:::elasticbeanstalk-ap-northeast-2-{self.account_id}/*",
                ]
            })

        return {
            "Version": "2012-10-17",
            "Statement": statements,
        }
