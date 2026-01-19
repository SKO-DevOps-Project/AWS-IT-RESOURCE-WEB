"""
Role Manager Handler Lambda for AWS Role Request System
Triggered by EventBridge Scheduler for role creation/deletion
"""
import os
import json
import boto3
from typing import Dict, Any

from models import RequestStatus
from services.role_manager import RoleManager
from services.dynamodb_repository import RoleRequestRepository
from services.mattermost_client import MattermostClient
from services.scheduler import Scheduler


def lambda_handler(event: Dict[str, Any], context: Any) -> Dict[str, Any]:
    """
    Lambda handler for role creation/deletion
    
    Event format:
    {
        "action": "create_role" | "delete_role",
        "request_id": "uuid"
    }
    """
    print(f"[RoleManagerHandler] Received event: {json.dumps(event)}")
    
    action = event.get("action")
    request_id = event.get("request_id")
    
    if not action or not request_id:
        print(f"[RoleManagerHandler] ERROR: Missing action or request_id")
        return {"statusCode": 400, "body": "Missing action or request_id"}
    
    print(f"[RoleManagerHandler] Action: {action}, Request ID: {request_id}")
    
    # Initialize services
    table_name = os.environ.get("DYNAMODB_TABLE", "RoleRequests")
    company_ip_range = os.environ.get("COMPANY_IP_RANGE", "0.0.0.0/0")
    
    repository = RoleRequestRepository(table_name=table_name)
    role_manager = RoleManager(company_ip_range=company_ip_range)
    mattermost_client = MattermostClient()
    scheduler = Scheduler()
    
    # Get request
    request = repository.get_by_id(request_id)
    if not request:
        print(f"[RoleManagerHandler] ERROR: Request {request_id} not found")
        return {"statusCode": 404, "body": f"Request {request_id} not found"}
    
    print(f"[RoleManagerHandler] Found request: user={request.iam_user_name}, env={request.env}, service={request.service}")
    
    if action == "create_role":
        return handle_create_role(request, repository, role_manager, mattermost_client, scheduler)
    elif action == "delete_role":
        return handle_delete_role(request, repository, role_manager, mattermost_client, scheduler)
    else:
        print(f"[RoleManagerHandler] ERROR: Unknown action: {action}")
        return {"statusCode": 400, "body": f"Unknown action: {action}"}


def handle_create_role(request, repository, role_manager, mattermost_client, scheduler):
    """Handle role creation"""
    print(f"[handle_create_role] Starting role creation for request: {request.request_id}")
    try:
        # Create role
        print(f"[handle_create_role] Calling role_manager.create_dynamic_role")
        role_info = role_manager.create_dynamic_role(request)
        print(f"[handle_create_role] Role created: {role_info}")
        
        # Update request
        print(f"[handle_create_role] Updating request status to ACTIVE")
        repository.update_status(
            request.request_id,
            RequestStatus.ACTIVE,
            role_arn=role_info["role_arn"],
            policy_arn=role_info["policy_arn"],
        )
        
        # Send DM to requester (detailed message)
        print(f"[handle_create_role] Sending DM to requester: {request.requester_mattermost_id}")
        
        role_name = role_info['role_arn'].split("/")[-1]
        
        # Permission type display names
        permission_type_names = {
            "read_only": "조회만",
            "read_update": "조회+수정",
            "read_update_create": "조회+수정+생성",
            "full": "전체(삭제포함)",
        }
        
        # Target service display names
        target_service_names = {
            "all": "전체",
            "ec2": "EC2",
            "rds": "RDS",
            "lambda": "Lambda",
            "s3": "S3",
        }
        
        perm_display = permission_type_names.get(
            request.permission_type, request.permission_type or "read_update"
        )
        target_services_str = request.target_services[0] if request.target_services else "all"
        target_display = target_service_names.get(target_services_str, target_services_str)
        
        # Get requester username
        requester_username = request.requester_name
        if not requester_username:
            try:
                user_info = mattermost_client.get_user_by_id(request.requester_mattermost_id)
                if user_info:
                    requester_username = user_info.get("username", "")
            except Exception as e:
                print(f"[handle_create_role] Failed to get username: {e}")
                requester_username = ""
        
        mattermost_client.send_dm(
            user_id=request.requester_mattermost_id,
            message=f"✅ AWS Role이 생성되었습니다!\n\n"
                   f"**요청자 Mattermost ID:** {requester_username}\n"
                   f"**요청 ID:** {request.request_id}\n"
                   f"**Role ARN:** {role_info['role_arn']}\n\n"
                   f"---\n"
                   f"## 🖥️ Console에서 사용하기 (Switch Role)\n"
                   f"1. AWS Console 우측 상단 → Switch Role\n"
                   f"2. Account: `680877507363`\n"
                   f"3. Role: `{role_name}`\n\n"
                   f"---\n"
                   f"## 💻 CLI에서 사용하기\n\n"
                   f"**방법 1: 환경변수 설정 (권장)**\n"
                   f"```bash\n"
                   f"# 1. assume-role 실행\n"
                   f"CREDS=$(aws sts assume-role --role-arn {role_info['role_arn']} --role-session-name {request.iam_user_name}-session --query 'Credentials' --output json)\n\n"
                   f"# 2. 환경변수 설정\n"
                   f"export AWS_ACCESS_KEY_ID=$(echo $CREDS | jq -r '.AccessKeyId')\n"
                   f"export AWS_SECRET_ACCESS_KEY=$(echo $CREDS | jq -r '.SecretAccessKey')\n"
                   f"export AWS_SESSION_TOKEN=$(echo $CREDS | jq -r '.SessionToken')\n\n"
                   f"# 3. 확인\n"
                   f"aws sts get-caller-identity\n"
                   f"```\n\n"
                   f"**방법 2: AWS Profile 설정**\n"
                   f"```bash\n"
                   f"# ~/.aws/credentials 에 추가\n"
                   f"[temp-role]\n"
                   f"aws_access_key_id = <AccessKeyId 값>\n"
                   f"aws_secret_access_key = <SecretAccessKey 값>\n"
                   f"aws_session_token = <SessionToken 값>\n\n"
                   f"# 사용 시\n"
                   f"aws s3 ls --profile temp-role\n"
                   f"```\n\n"
                   f"---\n"
                   f"**시작 시간:** {request.start_time.strftime('%Y-%m-%d %H:%M')} (KST)\n"
                   f"**종료 시간:** {request.end_time.strftime('%Y-%m-%d %H:%M')} (KST)\n"
                   f"**Env:** {request.env} | **Service:** {request.service}\n"
                   f"**권한 유형:** {perm_display} | **대상 서비스:** {target_display}",
        )
        
        print(f"[handle_create_role] SUCCESS")
        return {"statusCode": 200, "body": "Role created successfully"}
    
    except Exception as e:
        print(f"[handle_create_role] ERROR: {str(e)}")
        import traceback
        print(f"[handle_create_role] Traceback: {traceback.format_exc()}")
        
        # Update status to error
        repository.update_status(request.request_id, RequestStatus.ERROR)
        
        # Notify requester
        mattermost_client.send_dm(
            user_id=request.requester_mattermost_id,
            message=f"❌ Role 생성 중 오류가 발생했습니다.\n"
                   f"요청 ID: {request.request_id}\n"
                   f"오류: {str(e)}",
        )
        
        return {"statusCode": 500, "body": str(e)}


def handle_delete_role(request, repository, role_manager, mattermost_client, scheduler):
    """Handle role deletion"""
    print(f"[handle_delete_role] Starting role deletion for request: {request.request_id}")
    try:
        if request.role_arn and request.policy_arn:
            # Delete role
            print(f"[handle_delete_role] Deleting role: {request.role_arn}")
            role_manager.delete_dynamic_role(request.role_arn, request.policy_arn)
            print(f"[handle_delete_role] Role deleted")
        else:
            print(f"[handle_delete_role] No role_arn or policy_arn to delete")
        
        # Update request
        print(f"[handle_delete_role] Updating request status to EXPIRED")
        repository.update_status(request.request_id, RequestStatus.EXPIRED)
        
        # Clean up schedules
        print(f"[handle_delete_role] Cleaning up schedules")
        scheduler.delete_schedule(f"role-create-{request.request_id}")
        scheduler.delete_schedule(f"role-delete-{request.request_id}")
        
        # Send DM to requester
        print(f"[handle_delete_role] Sending DM to requester")
        mattermost_client.send_dm(
            user_id=request.requester_mattermost_id,
            message=f"🔒 AWS Role 권한이 만료되었습니다.\n\n"
                   f"**요청 ID:** {request.request_id}\n"
                   f"**Env:** {request.env}\n"
                   f"**Service:** {request.service}\n\n"
                   f"추가 권한이 필요하시면 다시 요청해주세요.",
        )
        
        print(f"[handle_delete_role] SUCCESS")
        return {"statusCode": 200, "body": "Role deleted successfully"}
    
    except Exception as e:
        print(f"[handle_delete_role] ERROR: {str(e)}")
        import traceback
        print(f"[handle_delete_role] Traceback: {traceback.format_exc()}")
        return {"statusCode": 500, "body": str(e)}
