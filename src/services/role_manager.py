"""
Role Manager Service for AWS Role Request System
Handles IAM Role and Policy creation/deletion
"""
import json
import boto3
from datetime import datetime
from typing import Dict, Any, Optional, List

from models import RoleRequest


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
        ],
        "update": [
            "ec2:StartInstances",
            "ec2:StopInstances",
            "ec2:RebootInstances",
            "ec2:ModifyInstanceAttribute",
            "ec2:ModifyVolume*",
            "ec2:CreateTags",
            "ec2:DeleteTags",
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
        ],
        "create": [
            "ec2:RunInstances",
            "ec2:CreateVolume",
            "ec2:CreateSnapshot",
            "ec2:CreateImage",
            "ec2:CreateSecurityGroup",
            "ec2:AuthorizeSecurityGroupIngress",
            "ec2:AuthorizeSecurityGroupEgress",
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
            "ec2:RevokeSecurityGroupIngress",
            "ec2:RevokeSecurityGroupEgress",
            "ec2:DeleteKeyPair",
            "ec2:ReleaseAddress",
            "ec2:DisassociateAddress",
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
        ],
        "create": [
            "elasticbeanstalk:CreateApplication",
            "elasticbeanstalk:CreateApplicationVersion",
            "elasticbeanstalk:CreateEnvironment",
            "elasticbeanstalk:CreateConfigurationTemplate",
            "elasticbeanstalk:CreateStorageLocation",
            "s3:PutObject",
            "s3:CreateBucket",
        ],
        "delete": [
            "elasticbeanstalk:DeleteApplication",
            "elasticbeanstalk:DeleteApplicationVersion",
            "elasticbeanstalk:DeleteEnvironmentConfiguration",
            "elasticbeanstalk:DeleteConfigurationTemplate",
            "elasticbeanstalk:TerminateEnvironment",
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
    ):
        self.iam_client = iam_client or boto3.client("iam")
        self.account_id = account_id or boto3.client("sts").get_caller_identity()["Account"]
        self.company_ip_range = company_ip_range or "0.0.0.0/0"
    
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
        timestamp = datetime.utcnow().strftime("%Y%m%d%H%M%S")
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
        
        role_response = self.iam_client.create_role(
            RoleName=role_name,
            AssumeRolePolicyDocument=json.dumps(trust_policy),
            Description=description,
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
        permission_policy = self._generate_permission_policy(request)
        
        policy_response = self.iam_client.create_policy(
            PolicyName=policy_name,
            PolicyDocument=json.dumps(permission_policy),
            Description=f"Policy for {role_name}",
        )
        policy_arn = policy_response["Policy"]["Arn"]
        print(f"[RoleManager] Policy created: {policy_arn}")
        
        # Attach policy to role
        self.iam_client.attach_role_policy(
            RoleName=role_name,
            PolicyArn=policy_arn,
        )
        print(f"[RoleManager] Policy attached to role")
        
        return {
            "role_arn": role_arn,
            "policy_arn": policy_arn,
            "role_name": role_name,
        }
    
    def delete_dynamic_role(self, role_arn: str, policy_arn: str) -> None:
        """
        Delete dynamic role and policy
        
        Args:
            role_arn: Role ARN to delete
            policy_arn: Policy ARN to delete
        """
        role_name = role_arn.split("/")[-1]
        
        # Detach policy from role
        try:
            self.iam_client.detach_role_policy(
                RoleName=role_name,
                PolicyArn=policy_arn,
            )
        except self.iam_client.exceptions.NoSuchEntityException:
            pass
        
        # Delete role
        try:
            self.iam_client.delete_role(RoleName=role_name)
        except self.iam_client.exceptions.NoSuchEntityException:
            pass
        
        # Delete policy
        try:
            self.iam_client.delete_policy(PolicyArn=policy_arn)
        except self.iam_client.exceptions.NoSuchEntityException:
            pass
    
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
        if 'all' in target_services:
            services_to_include = ['ec2', 'rds', 'lambda', 's3', 'elasticbeanstalk']
        else:
            services_to_include = target_services
        
        # Collect actions based on permission type
        read_actions = []
        tagged_actions = []
        create_actions = []
        
        for svc in services_to_include:
            if svc in SERVICE_PERMISSIONS:
                perms = SERVICE_PERMISSIONS[svc]
                
                # Always include read permissions
                read_actions.extend(perms.get('read', []))
                
                if permission_type in ['read_update', 'read_update_create', 'full']:
                    tagged_actions.extend(perms.get('update', []))
                
                if permission_type in ['read_update_create', 'full']:
                    create_actions.extend(perms.get('create', []))
                
                if permission_type == 'full':
                    tagged_actions.extend(perms.get('delete', []))
        
        # Statement 1: Read-only permissions (no tag condition)
        if read_actions:
            statements.append({
                "Sid": "ReadOnlyAccess",
                "Effect": "Allow",
                "Action": list(set(read_actions)),
                "Resource": "*",
            })
        
        # Statement 2: Tag-based permissions (update/delete)
        if tagged_actions:
            # Separate SSM actions from other actions for special condition
            ssm_session_actions = [a for a in tagged_actions if a.startswith('ssm:') and 'Session' in a]
            ssm_message_actions = [a for a in tagged_actions if a.startswith('ssmmessages:') or a.startswith('ec2messages:')]
            other_tagged_actions = [a for a in tagged_actions if a not in ssm_session_actions and a not in ssm_message_actions]
            
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
            
            # SSM Session actions with EC2 instance tag condition
            if ssm_session_actions:
                statements.append({
                    "Sid": "SSMSessionAccess",
                    "Effect": "Allow",
                    "Action": list(set(ssm_session_actions)),
                    "Resource": "arn:aws:ec2:*:*:instance/*",
                    "Condition": {
                        "StringEquals": {
                            "ssm:resourceTag/Env": request.env,
                            "ssm:resourceTag/Service": request.service,
                        }
                    }
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
            
            # SSM Messages permissions (no resource restriction)
            if ssm_message_actions:
                statements.append({
                    "Sid": "SSMMessagesAccess",
                    "Effect": "Allow",
                    "Action": list(set(ssm_message_actions)),
                    "Resource": "*"
                })
        
        # Statement 3: Create permissions with tag enforcement
        if create_actions:
            # Allow create with required tags
            statements.append({
                "Sid": "CreateWithTags",
                "Effect": "Allow",
                "Action": list(set(create_actions)),
                "Resource": "*",
                "Condition": {
                    "StringEquals": {
                        "aws:RequestTag/Env": request.env,
                        "aws:RequestTag/Service": request.service,
                    }
                }
            })
            
            # Also allow CreateTags for new resources
            statements.append({
                "Sid": "AllowCreateTags",
                "Effect": "Allow",
                "Action": [
                    "ec2:CreateTags",
                    "rds:AddTagsToResource",
                    "lambda:TagResource",
                    "s3:PutBucketTagging",
                    "s3:PutObjectTagging",
                ],
                "Resource": "*",
                "Condition": {
                    "StringEquals": {
                        "aws:RequestTag/Env": request.env,
                        "aws:RequestTag/Service": request.service,
                    }
                }
            })
        
        return {
            "Version": "2012-10-17",
            "Statement": statements,
        }
