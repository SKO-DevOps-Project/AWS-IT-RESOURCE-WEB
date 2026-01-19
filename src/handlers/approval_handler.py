"""
Approval Handler Lambda for AWS Role Request System
Handles approval/rejection interactive actions
"""
import os
import json
from datetime import datetime, timezone, timedelta
from typing import Dict, Any, Optional

from models import RequestStatus
from services.dynamodb_repository import RoleRequestRepository
from services.scheduler import Scheduler
from services.mattermost_client import MattermostClient
from services.role_manager import RoleManager

# Korea Standard Time (UTC+9)
KST = timezone(timedelta(hours=9))


class ApprovalHandler:
    """Handles approval/rejection actions"""
    
    def __init__(
        self,
        repository=None,
        scheduler=None,
        mattermost_client=None,
        role_manager=None,
    ):
        self.repository = repository
        self.scheduler = scheduler
        self.mattermost_client = mattermost_client
        self.role_manager = role_manager
    
    def handle_interactive_action(self, event: Dict[str, Any]) -> Dict[str, Any]:
        """
        Handle interactive button click
        
        Args:
            event: Mattermost interactive action event
        
        Returns:
            Response for Mattermost
        """
        context = event.get("context", {})
        action = context.get("action")
        request_id = context.get("request_id")
        approver_id = event.get("user_id")
        trigger_id = event.get("trigger_id")
        
        if action == "approve":
            return self.handle_approve(request_id, approver_id, event)
        elif action == "reject":
            # Directly reject without dialog (simplified flow)
            return self.handle_reject(request_id, approver_id, "관리자에 의해 반려됨")
        elif action == "revoke":
            return self.handle_revoke(request_id, approver_id, event)
        
        return {}
    
    def _get_username(self, user_id: str) -> str:
        """Get username from user_id, fallback to user_id if not found"""
        if self.mattermost_client:
            try:
                user = self.mattermost_client.get_user_by_id(user_id)
                if user:
                    return user.get("username", user_id)
            except Exception as e:
                print(f"[_get_username] Failed to get username for {user_id}: {e}")
        return user_id
    
    def handle_approve(
        self,
        request_id: str,
        approver_id: str,
        event: Dict[str, Any],
    ) -> Dict[str, Any]:
        """
        Handle approval
        
        Args:
            request_id: Request ID
            approver_id: Approver user ID
            event: Full event data
        
        Returns:
            Response for Mattermost
        """
        print(f"[handle_approve] Starting approval for request: {request_id}")
        
        if not self.repository:
            return {"update": {"message": "❌ Repository not configured"}}
        
        # Get request
        request = self.repository.get_by_id(request_id)
        if not request:
            return {"update": {"message": "❌ 요청을 찾을 수 없습니다"}}
        
        # Get approver username
        approver_username = self._get_username(approver_id)
        
        # Get current time in KST
        now_kst = datetime.now(KST)
        
        # Make request times timezone-aware (assume they are in KST)
        start_time = request.start_time
        end_time = request.end_time
        if start_time.tzinfo is None:
            start_time = start_time.replace(tzinfo=KST)
        if end_time.tzinfo is None:
            end_time = end_time.replace(tzinfo=KST)
        
        print(f"[handle_approve] Current KST: {now_kst}")
        print(f"[handle_approve] Start time: {start_time}")
        print(f"[handle_approve] End time: {end_time}")
        
        # Check if end time is already past
        if end_time <= now_kst:
            print(f"[handle_approve] End time is in the past, rejecting")
            return {"update": {"message": "❌ 종료 시간이 이미 지났습니다. 새로운 요청을 해주세요."}}
        
        # Update status to approved
        self.repository.update_status(
            request_id,
            RequestStatus.APPROVED,
            approver_id=approver_id,
        )
        
        # Check if start time is in the past (should create role immediately)
        if start_time <= now_kst:
            print(f"[handle_approve] Start time is in the past, creating role immediately")
            # Create role immediately
            if self.role_manager:
                try:
                    role_info = self.role_manager.create_dynamic_role(request)
                    print(f"[handle_approve] Role created: {role_info}")
                    
                    # Update request with role info
                    self.repository.update_status(
                        request_id,
                        RequestStatus.ACTIVE,
                        role_arn=role_info["role_arn"],
                        policy_arn=role_info["policy_arn"],
                    )
                    
                    # Send role info to requester (detailed message like master request)
                    if self.mattermost_client:
                        try:
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
                            
                            # Get requester username for DM
                            requester_username = request.requester_name
                            if not requester_username:
                                requester_username = self._get_username(request.requester_mattermost_id)
                            
                            self.mattermost_client.send_dm(
                                user_id=request.requester_mattermost_id,
                                message=f"✅ AWS Role이 생성되었습니다!\n\n"
                                       f"**요청자 Mattermost ID:** {requester_username}\n"
                                       f"**요청 ID:** {request_id}\n"
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
                                       f"**시작 시간:** {start_time.strftime('%Y-%m-%d %H:%M')} (KST)\n"
                                       f"**종료 시간:** {end_time.strftime('%Y-%m-%d %H:%M')} (KST)\n"
                                       f"**Env:** {request.env} | **Service:** {request.service}\n"
                                       f"**권한 유형:** {perm_display} | **대상 서비스:** {target_display}",
                            )
                        except Exception as e:
                            print(f"[handle_approve] Failed to send DM: {e}")
                    
                    # Schedule only the end (deletion)
                    if self.scheduler:
                        try:
                            self.scheduler.create_end_schedule(request)
                            print(f"[handle_approve] End schedule created")
                        except Exception as e:
                            print(f"[handle_approve] Failed to create end schedule: {e}")
                    
                except Exception as e:
                    print(f"[handle_approve] Failed to create role: {e}")
                    return {"update": {"message": f"❌ Role 생성 실패: {str(e)}"}}
        else:
            print(f"[handle_approve] Start time is in the future, creating schedules")
            # Start time is in the future, create both schedules
            if self.scheduler:
                try:
                    self.scheduler.create_start_schedule(request)
                    self.scheduler.create_end_schedule(request)
                    print(f"[handle_approve] Schedules created")
                except Exception as e:
                    print(f"[handle_approve] Failed to create schedules: {e}")
                    return {"update": {"message": f"❌ 스케줄 생성 실패: {str(e)}"}}
            
            # Send DM to requester about scheduled approval
            if self.mattermost_client:
                try:
                    # Get requester username for DM
                    requester_username = request.requester_name
                    if not requester_username:
                        requester_username = self._get_username(request.requester_mattermost_id)
                    
                    self.mattermost_client.send_dm(
                        user_id=request.requester_mattermost_id,
                        message=f"✅ 권한 요청이 승인되었습니다.\n\n"
                               f"**요청자 Mattermost ID:** {requester_username}\n"
                               f"**요청 ID:** {request_id}\n"
                               f"**시작 시간:** {start_time.strftime('%Y-%m-%d %H:%M')} (KST)\n"
                               f"**종료 시간:** {end_time.strftime('%Y-%m-%d %H:%M')} (KST)\n\n"
                               f"시작 시간에 Role이 자동으로 생성됩니다.",
                    )
                except Exception as e:
                    print(f"[handle_approve] Failed to send DM: {e}")
        
        # Send approval status message to approval channel (new message instead of update due to 403)
        if self.mattermost_client:
            try:
                from services.mattermost_client import Attachment, Action
                
                # Get callback URL from environment or construct it
                callback_url = os.environ.get("CALLBACK_URL", "")
                approval_channel_id = os.environ.get("APPROVAL_CHANNEL_ID", "")
                
                # Get requester username
                requester_username = request.requester_name
                if not requester_username:
                    requester_username = self._get_username(request.requester_mattermost_id)
                
                updated_attachment = Attachment(
                    fallback=f"승인됨: {requester_username}",
                    color="#00FF00",
                    title="✅ 승인됨",
                    text=f"**요청자:** {requester_username}\n"
                         f"**IAM User:** {request.iam_user_name}\n"
                         f"**Env:** {request.env} | **Service:** {request.service}\n"
                         f"**시간:** {start_time.strftime('%Y-%m-%d %H:%M')} ~ {end_time.strftime('%Y-%m-%d %H:%M')} (KST)\n\n"
                         f"**승인자:** {approver_username}\n"
                         f"**요청 ID:** {request_id}",
                    actions=[
                        Action(
                            id="revoke",
                            name="🔄 권한 회수",
                            integration={
                                "url": callback_url,
                                "context": {
                                    "action": "revoke",
                                    "request_id": request_id,
                                },
                            },
                            style="danger",
                        ),
                    ],
                )
                
                # Try to update first, if fails send new message
                if request.post_id:
                    try:
                        self.mattermost_client.update_message(
                            post_id=request.post_id,
                            message=f"📋 권한 요청 - 승인됨",
                            attachments=[updated_attachment],
                        )
                    except Exception as update_error:
                        print(f"[handle_approve] Failed to update message (403?): {update_error}")
                        # Send new message to approval channel instead
                        if approval_channel_id:
                            self.mattermost_client.send_to_channel(
                                channel_id=approval_channel_id,
                                message=f"📋 권한 요청 - 승인됨",
                                attachments=[updated_attachment],
                            )
                elif approval_channel_id:
                    self.mattermost_client.send_to_channel(
                        channel_id=approval_channel_id,
                        message=f"📋 권한 요청 - 승인됨",
                        attachments=[updated_attachment],
                    )
            except Exception as e:
                print(f"[handle_approve] Failed to send approval message: {e}")
        
        print(f"[handle_approve] Approval completed successfully")
        return {"update": {"message": "✅ 승인되었습니다"}}
    
    def handle_reject(
        self,
        request_id: str,
        approver_id: str,
        rejection_reason: str,
    ) -> Dict[str, Any]:
        """
        Handle rejection
        
        Args:
            request_id: Request ID
            approver_id: Approver user ID
            rejection_reason: Reason for rejection
        
        Returns:
            Response for Mattermost
        """
        if not self.repository:
            return {"update": {"message": "❌ Repository not configured"}}
        
        # Get request
        request = self.repository.get_by_id(request_id)
        if not request:
            return {"update": {"message": "❌ 요청을 찾을 수 없습니다"}}
        
        # Check if already rejected
        if request.status == RequestStatus.REJECTED:
            return {"update": {"message": "❌ 이미 반려된 요청입니다"}}
        
        # Get rejecter username
        rejecter_username = self._get_username(approver_id)
        
        # Get requester username
        requester_username = request.requester_name
        if not requester_username:
            requester_username = self._get_username(request.requester_mattermost_id)
        
        # Update status
        self.repository.update_status(
            request_id,
            RequestStatus.REJECTED,
            approver_id=approver_id,
            rejection_reason=rejection_reason,
        )
        
        # Send rejection status message to approval channel (new message instead of update due to 403)
        if self.mattermost_client:
            try:
                from services.mattermost_client import Attachment
                approval_channel_id = os.environ.get("APPROVAL_CHANNEL_ID", "")
                
                updated_attachment = Attachment(
                    fallback=f"반려됨: {requester_username}",
                    color="#FF0000",
                    title="❌ 반려됨",
                    text=f"**요청자:** {requester_username}\n"
                         f"**IAM User:** {request.iam_user_name}\n"
                         f"**Env:** {request.env} | **Service:** {request.service}\n\n"
                         f"**반려자:** {rejecter_username}\n"
                         f"**사유:** {rejection_reason}",
                )
                
                # Try to update first, if fails send new message
                if request.post_id:
                    try:
                        self.mattermost_client.update_message(
                            post_id=request.post_id,
                            message=f"📋 권한 요청 - 반려됨",
                            attachments=[updated_attachment],
                        )
                    except Exception as update_error:
                        print(f"[handle_reject] Failed to update message (403?): {update_error}")
                        # Send new message to approval channel instead
                        if approval_channel_id:
                            self.mattermost_client.send_to_channel(
                                channel_id=approval_channel_id,
                                message=f"📋 권한 요청 - 반려됨",
                                attachments=[updated_attachment],
                            )
                elif approval_channel_id:
                    self.mattermost_client.send_to_channel(
                        channel_id=approval_channel_id,
                        message=f"📋 권한 요청 - 반려됨",
                        attachments=[updated_attachment],
                    )
            except Exception as e:
                print(f"[handle_reject] Failed to send rejection message: {e}")
        
        # Send DM to requester
        if self.mattermost_client:
            try:
                self.mattermost_client.send_dm(
                    user_id=request.requester_mattermost_id,
                    message=f"❌ 권한 요청이 반려되었습니다.\n"
                           f"**요청 ID:** {request_id}\n"
                           f"**반려 사유:** {rejection_reason}",
                )
            except Exception as e:
                print(f"Failed to send DM: {e}")
        
        return {"update": {"message": "❌ 반려 처리되었습니다"}}
    
    def handle_revoke(
        self,
        request_id: str,
        revoker_id: str,
        event: Dict[str, Any],
    ) -> Dict[str, Any]:
        """
        Handle role revocation (admin forcefully removes active role)
        
        Args:
            request_id: Request ID
            revoker_id: Admin user ID who is revoking
            event: Full event data
        
        Returns:
            Response for Mattermost
        """
        print(f"[handle_revoke] Starting revocation for request: {request_id}")
        
        if not self.repository:
            return {"update": {"message": "❌ Repository not configured"}}
        
        # Get request
        request = self.repository.get_by_id(request_id)
        if not request:
            return {"update": {"message": "❌ 요청을 찾을 수 없습니다"}}
        
        # Get revoker username
        revoker_username = self._get_username(revoker_id)
        
        # Check if role exists and can be revoked
        if request.status not in [RequestStatus.ACTIVE, RequestStatus.APPROVED]:
            return {"update": {"message": f"❌ 현재 상태({request.status})에서는 권한을 회수할 수 없습니다"}}
        
        try:
            # Delete role if it exists
            if request.role_arn and request.policy_arn and self.role_manager:
                print(f"[handle_revoke] Deleting role: {request.role_arn}")
                self.role_manager.delete_dynamic_role(request.role_arn, request.policy_arn)
                print(f"[handle_revoke] Role deleted")
            
            # Delete schedules
            if self.scheduler:
                self.scheduler.delete_schedule(f"role-create-{request_id}")
                self.scheduler.delete_schedule(f"role-delete-{request_id}")
            
            # Update status to revoked
            self.repository.update_status(
                request_id,
                RequestStatus.REVOKED,
                approver_id=revoker_id,
            )
            
            # Send revoke status message to approval channel (new message instead of update due to 403)
            if self.mattermost_client:
                try:
                    from services.mattermost_client import Attachment
                    approval_channel_id = os.environ.get("APPROVAL_CHANNEL_ID", "")
                    
                    # Get requester username
                    requester_username = request.requester_name
                    if not requester_username:
                        requester_username = self._get_username(request.requester_mattermost_id)
                    
                    updated_attachment = Attachment(
                        fallback=f"권한 회수됨: {requester_username}",
                        color="#FF0000",
                        title="🔄 권한이 회수되었습니다",
                        text=f"**요청자:** {requester_username}\n"
                             f"**IAM User:** {request.iam_user_name}\n"
                             f"**Env:** {request.env} | **Service:** {request.service}\n\n"
                             f"**회수자:** {revoker_username}\n"
                             f"**요청 ID:** {request_id}",
                    )
                    
                    # Try to update first, if fails send new message
                    if request.post_id:
                        try:
                            self.mattermost_client.update_message(
                                post_id=request.post_id,
                                message=f"📋 권한 요청 - 권한 회수됨",
                                attachments=[updated_attachment],
                            )
                        except Exception as update_error:
                            print(f"[handle_revoke] Failed to update message (403?): {update_error}")
                            # Send new message to approval channel instead
                            if approval_channel_id:
                                self.mattermost_client.send_to_channel(
                                    channel_id=approval_channel_id,
                                    message=f"📋 권한 요청 - 권한 회수됨",
                                    attachments=[updated_attachment],
                                )
                    elif approval_channel_id:
                        self.mattermost_client.send_to_channel(
                            channel_id=approval_channel_id,
                            message=f"📋 권한 요청 - 권한 회수됨",
                            attachments=[updated_attachment],
                        )
                except Exception as e:
                    print(f"[handle_revoke] Failed to send revoke message: {e}")
            
            # Send DM to requester
            if self.mattermost_client:
                try:
                    self.mattermost_client.send_dm(
                        user_id=request.requester_mattermost_id,
                        message=f"🔄 AWS Role 권한이 관리자에 의해 회수되었습니다.\n\n"
                               f"**요청 ID:** {request_id}\n"
                               f"**Env:** {request.env}\n"
                               f"**Service:** {request.service}\n\n"
                               f"문의사항이 있으시면 관리자에게 연락해주세요.",
                    )
                except Exception as e:
                    print(f"[handle_revoke] Failed to send DM: {e}")
            
            print(f"[handle_revoke] Revocation completed successfully")
            return {"update": {"message": "🔄 권한이 회수되었습니다"}}
            
        except Exception as e:
            print(f"[handle_revoke] Error: {e}")
            return {"update": {"message": f"❌ 권한 회수 실패: {str(e)}"}}


def lambda_handler(event: Dict[str, Any], context: Any) -> Dict[str, Any]:
    """Lambda handler for interactive actions"""
    
    # Initialize services
    table_name = os.environ.get("DYNAMODB_TABLE", "RoleRequests")
    company_ip_range = os.environ.get("COMPANY_IP_RANGE", "0.0.0.0/0")
    
    # Get callback URL from request context
    request_context = event.get("requestContext", {})
    domain_name = request_context.get("domainName", "")
    stage = request_context.get("stage", "prod")
    callback_url = f"https://{domain_name}/{stage}/interactive" if domain_name else ""
    os.environ["CALLBACK_URL"] = callback_url
    
    repository = RoleRequestRepository(table_name=table_name)
    scheduler = Scheduler()
    mattermost_client = MattermostClient()
    role_manager = RoleManager(company_ip_range=company_ip_range)
    
    handler = ApprovalHandler(
        repository=repository,
        scheduler=scheduler,
        mattermost_client=mattermost_client,
        role_manager=role_manager,
    )
    
    # Parse the body - Mattermost sends JSON directly in body
    body = event.get("body", "")
    print(f"Raw body: {body}")  # Debug logging
    
    params = {}
    if isinstance(body, str):
        # Try to parse as JSON first
        try:
            params = json.loads(body)
        except json.JSONDecodeError:
            # If not JSON, try URL-encoded form data
            import urllib.parse
            parsed = dict(urllib.parse.parse_qsl(body))
            # Mattermost interactive messages send JSON in 'payload' field
            if "payload" in parsed:
                params = json.loads(parsed["payload"])
            else:
                params = parsed
    else:
        params = body
    
    print(f"Parsed params: {json.dumps(params)}")  # Debug logging
    
    result = handler.handle_interactive_action(params)
    
    return {
        "statusCode": 200,
        "headers": {"Content-Type": "application/json"},
        "body": json.dumps(result),
    }
