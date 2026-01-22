"""
Request Handler Lambda for AWS Role Request System
Handles /request-role and /master-request-role slash commands
"""
import os
import re
import uuid
import json
from datetime import datetime, timedelta, timezone
from typing import Dict, Any, Optional, Tuple

from models import (
    RoleRequest,
    RequestStatus,
    ValidationResult,
    VALID_ENVS,
    VALID_SERVICES,
    SERVICE_DISPLAY_NAMES,
)
from services.request_validator import RequestValidator
from services.mattermost_client import (
    MattermostClient,
    create_approval_message,
)


# Admin user IDs (loaded from environment)
ADMIN_USER_IDS = os.environ.get("ADMIN_USER_IDS", "").split(",")
APPROVAL_CHANNEL_ID = os.environ.get("APPROVAL_CHANNEL_ID", "")
REQUEST_CHANNEL_ID = os.environ.get("REQUEST_CHANNEL_ID", "")

# Korea Standard Time (UTC+9)
KST = timezone(timedelta(hours=9))


REQUEST_TEMPLATE = """------------
- IAM user명 : 
- Env (고유 Env: {envs})
- Service (고유 Service: {services})
- 시간 : ex, 09-18시 또는 2025-01-15 09:00 ~ 2025-01-15 18:00
- 목적 : 
------------

위 템플릿을 복사하여 작성해주세요.""".format(
    envs=" / ".join(VALID_ENVS),
    services=", ".join(VALID_SERVICES),
)


def create_request_dialog(
    is_master: bool = False,
    user_options: list = None,
    work_request_options: list = None,
    preselected_work_request_id: str = None,
) -> dict:
    """Create interactive dialog for role request

    Args:
        is_master: Whether this is a master (admin) request
        user_options: List of user options for master dialog (format: [{"text": "username", "value": "user_id"}])
        work_request_options: List of work request options (format: [{"text": "description", "value": "request_id"}])
        preselected_work_request_id: Pre-selected work request ID (from button click)
    """
    elements = []

    # Add work request selection at the top (optional)
    if work_request_options:
        work_request_element = {
            "display_name": "연관 업무 요청",
            "name": "work_request_id",
            "type": "select",
            "options": [{"text": "(선택 안함)", "value": ""}] + work_request_options,
            "help_text": "이 권한 요청과 연결할 업무 요청을 선택하세요",
            "optional": True,
        }
        # Set default value if preselected
        if preselected_work_request_id:
            work_request_element["default"] = preselected_work_request_id
        elements.append(work_request_element)

    # For master request, add target user selection at the top
    if is_master and user_options:
        elements.append({
            "display_name": "권한 부여 대상자",
            "name": "target_user_id",
            "type": "select",
            "options": user_options,
            "help_text": "권한을 부여할 Mattermost 사용자를 선택하세요",
        })

    elements.extend([
        {
            "display_name": "IAM User명",
            "name": "iam_user_name",
            "type": "text",
            "placeholder": "예: he12569",
            "help_text": "AWS IAM 사용자 이름을 입력하세요",
        },
        {
            "display_name": "Environment",
            "name": "env",
            "type": "select",
            "options": [
                {"text": env, "value": env} for env in VALID_ENVS
            ],
            "help_text": "환경을 선택하세요",
        },
        {
            "display_name": "Service",
            "name": "service",
            "type": "select",
            "options": [
                {
                    "text": f"{svc} ({SERVICE_DISPLAY_NAMES.get(svc, svc)})" if SERVICE_DISPLAY_NAMES.get(svc) else svc,
                    "value": svc
                } for svc in VALID_SERVICES
            ],
            "help_text": "서비스를 선택하세요",
        },
        {
            "display_name": "권한 유형",
            "name": "permission_type",
            "type": "select",
            "default": "read_update",
            "options": [
                {"text": "조회만 (Read Only)", "value": "read_only"},
                {"text": "조회 + 수정 (Read + Update)", "value": "read_update"},
                {"text": "조회 + 수정 + 생성 (Read + Update + Create)", "value": "read_update_create"},
                {"text": "전체 (Full - 삭제 포함)", "value": "full"},
            ],
            "help_text": "필요한 권한 수준을 선택하세요",
        },
        {
            "display_name": "대상 AWS 서비스",
            "name": "target_services",
            "type": "select",
            "default": "all",
            "options": [
                {"text": "전체 (EC2+SSM, RDS, Lambda, S3, EB)", "value": "all"},
                {"text": "EC2만 (SSM 접속 포함)", "value": "ec2"},
                {"text": "RDS만", "value": "rds"},
                {"text": "Lambda만", "value": "lambda"},
                {"text": "S3만", "value": "s3"},
                {"text": "ElasticBeanstalk만", "value": "elasticbeanstalk"},
            ],
            "help_text": "권한이 필요한 AWS 서비스를 선택하세요",
        },
        {
            "display_name": "시작 시간",
            "name": "start_time",
            "type": "text",
            "placeholder": "예: 10:00 또는 2026-01-15 10:00 (비워두면 즉시)",
            "help_text": "권한 시작 시간 (KST, 비워두면 즉시 시작)",
            "optional": True,
        },
        {
            "display_name": "종료 시간",
            "name": "end_time",
            "type": "text",
            "placeholder": "예: 18:00 또는 2026-01-15 18:00",
            "help_text": "권한 종료 시간 (KST, 최대 24시간)",
        },
        {
            "display_name": "목적",
            "name": "purpose",
            "type": "textarea",
            "placeholder": "권한이 필요한 이유를 입력하세요",
            "help_text": "권한 부여 사유를 기록합니다" if is_master else "승인자가 검토할 수 있도록 상세히 작성해주세요",
        },
    ])
    
    return {
        "callback_id": "master_request_dialog" if is_master else "role_request_dialog",
        "title": "AWS Role 즉시 권한 부여 (관리자)" if is_master else "AWS Role 권한 요청",
        "submit_label": "즉시 부여" if is_master else "요청",
        "elements": elements,
    }


class RequestHandler:
    """Handles slash command requests"""

    def __init__(
        self,
        validator: Optional[RequestValidator] = None,
        mattermost_client: Optional[MattermostClient] = None,
        repository=None,
        role_manager=None,
        scheduler=None,
        callback_url: str = "",
    ):
        self.validator = validator or RequestValidator()
        self.mattermost_client = mattermost_client or MattermostClient()
        self.repository = repository
        self.role_manager = role_manager
        self.scheduler = scheduler
        self.callback_url = callback_url

    def is_admin(self, user_id: str) -> bool:
        """Check if user is an admin"""
        return user_id in ADMIN_USER_IDS

    def get_work_request_options(self) -> list:
        """Get list of active work requests for dropdown"""
        import boto3

        try:
            dynamodb = boto3.resource('dynamodb')
            work_requests_table = dynamodb.Table('WorkRequests')

            # Scan for pending and in_progress work requests
            result = work_requests_table.scan(Limit=50)
            items = result.get('Items', [])

            # Filter and sort by created_at descending
            active_items = [
                item for item in items
                if item.get('status') in ['pending', 'in_progress']
            ]
            active_items.sort(key=lambda x: x.get('created_at', ''), reverse=True)

            # Convert to dropdown options
            options = []
            for item in active_items[:20]:  # Limit to 20 most recent
                service_display = item.get('service_display_name', item.get('service_name', ''))
                description = item.get('description', '')[:30]
                requester = item.get('requester_name', '')
                options.append({
                    "text": f"[{service_display}] {description}... ({requester})",
                    "value": item.get('request_id', ''),
                })

            return options
        except Exception as e:
            print(f"[get_work_request_options] Error: {e}")
            return []
    
    def handle_slash_command(self, event: Dict[str, Any]) -> Dict[str, Any]:
        """
        Handle /request-role slash command
        
        Args:
            event: Mattermost slash command event
        
        Returns:
            Response for Mattermost
        """
        text = event.get("text", "").strip()
        user_id = event.get("user_id", "")
        user_name = event.get("user_name", "")
        channel_id = event.get("channel_id", "")
        trigger_id = event.get("trigger_id", "")
        
        # If no text, open dialog
        if not text:
            # Open interactive dialog
            if trigger_id and self.mattermost_client:
                try:
                    # Get work request options for dropdown
                    work_request_options = self.get_work_request_options()
                    dialog = create_request_dialog(work_request_options=work_request_options)
                    self.mattermost_client.open_dialog(
                        trigger_id=trigger_id,
                        url=self.callback_url.replace("/interactive", "/dialog"),
                        dialog=dialog,
                    )
                    return {"response_type": "ephemeral", "text": ""}
                except Exception as e:
                    print(f"Failed to open dialog: {e}")
                    # Fallback to template
                    return self._response(REQUEST_TEMPLATE)
            return self._response(REQUEST_TEMPLATE)
        
        # Parse the request (for backward compatibility with text input)
        parsed = self._parse_request_text(text)
        if parsed is None:
            return self._error_response(
                "요청 형식이 올바르지 않습니다. /request-role 을 입력하여 다이얼로그를 열어주세요."
            )
        
        iam_user_name, env, service, start_time, end_time, purpose = parsed
        
        # Validate
        validation_result = self.validator.validate(
            iam_user_name=iam_user_name,
            env=env,
            service=service,
            start_time=start_time,
            end_time=end_time,
            purpose=purpose,
        )
        
        if not validation_result.is_valid:
            error_messages = "\n".join(
                f"- {e.field}: {e.message}" for e in validation_result.errors
            )
            return self._error_response(f"입력 오류:\n{error_messages}")
        
        # Validate IAM user exists
        iam_validation = self.validator.validate_iam_user_exists(iam_user_name)
        if not iam_validation.is_valid:
            error_messages = "\n".join(
                f"- {e.field}: {e.message}" for e in iam_validation.errors
            )
            return self._error_response(f"입력 오류:\n{error_messages}")
        
        # Create request
        request = RoleRequest(
            request_id=str(uuid.uuid4()),
            requester_mattermost_id=user_id,
            requester_name=user_name,
            iam_user_name=iam_user_name,
            env=env,
            service=service,
            start_time=start_time,
            end_time=end_time,
            purpose=purpose,
            status=RequestStatus.PENDING,
            is_master_request=False,
        )
        
        # Save to repository
        if self.repository:
            self.repository.save(request)
        
        # Forward to approval channel
        self._forward_to_approval_channel(request)
        
        return self._response(
            f"✅ 권한 요청이 제출되었습니다.\n"
            f"요청 ID: {request.request_id}\n"
            f"담당자 승인 후 알림을 받으실 수 있습니다."
        )
    
    def handle_dialog_submission(self, event: Dict[str, Any]) -> Dict[str, Any]:
        """
        Handle dialog form submission

        Args:
            event: Mattermost dialog submission event

        Returns:
            Response for Mattermost
        """
        submission = event.get("submission", {})
        user_id = event.get("user_id", "")
        user_name = event.get("user_name", "")
        callback_id = event.get("callback_id", "")

        print(f"[handle_dialog_submission] callback_id: {callback_id}")
        print(f"[handle_dialog_submission] submission: {submission}")
        print(f"[handle_dialog_submission] user_id: {user_id}, user_name: {user_name}")

        # If user_name is empty, get it from API
        if not user_name and user_id and self.mattermost_client:
            try:
                user_info = self.mattermost_client.get_user_by_id(user_id)
                if user_info:
                    user_name = user_info.get("username", "")
                    print(f"[handle_dialog_submission] Got username from API: {user_name}")
            except Exception as e:
                print(f"[handle_dialog_submission] Failed to get username: {e}")

        # Parse work_request_id from callback_id if present (from button click)
        # Format: "role_request_dialog:work_request:{work_request_id}"
        work_request_id = None
        if ":work_request:" in callback_id:
            parts = callback_id.split(":work_request:")
            work_request_id = parts[1] if len(parts) > 1 else None
            callback_id = parts[0]  # Get base callback_id
            print(f"[handle_dialog_submission] Extracted work_request_id from callback_id: {work_request_id}")

        # Also check submission for work_request_id (from dropdown selection)
        # Dropdown selection takes priority if present
        submitted_work_request_id = submission.get("work_request_id", "").strip()
        if submitted_work_request_id:
            work_request_id = submitted_work_request_id
            print(f"[handle_dialog_submission] Using work_request_id from dropdown: {work_request_id}")

        # Check if this is a master request dialog
        is_master = callback_id == "master_request_dialog"

        if callback_id not in ["role_request_dialog", "master_request_dialog"]:
            return {}
        
        # For master request, check admin permission
        if is_master and not self.is_admin(user_id):
            return {"errors": {"iam_user_name": "관리자 권한이 없습니다"}}
        
        # Extract fields
        iam_user_name = submission.get("iam_user_name", "").strip()
        env = submission.get("env", "")
        service = submission.get("service", "")
        permission_type = submission.get("permission_type", "read_update")
        target_services_str = submission.get("target_services", "all")
        start_time_str = submission.get("start_time", "").strip()
        end_time_str = submission.get("end_time", "").strip()
        purpose = submission.get("purpose", "").strip()
        
        # For master request, get target user ID (who will receive the DM)
        target_user_id = submission.get("target_user_id", "") if is_master else user_id
        target_user_name = user_name
        
        # If master request and target user selected, get their username
        if is_master and target_user_id and self.mattermost_client:
            try:
                target_user = self.mattermost_client.get_user_by_id(target_user_id)
                if target_user:
                    target_user_name = target_user.get("username", user_name)
            except Exception as e:
                print(f"Failed to get target user info: {e}")
        
        # Convert target_services to list
        target_services = [target_services_str] if target_services_str else ["all"]
        
        # Parse times
        now_kst = datetime.now(KST)
        
        # If start_time is empty, use now (for both master and normal requests)
        if not start_time_str:
            start_time = datetime(now_kst.year, now_kst.month, now_kst.day, now_kst.hour, now_kst.minute)
        else:
            start_time = self._parse_single_time(start_time_str)
        
        end_time = self._parse_single_time(end_time_str)
        
        if start_time is None:
            return {"errors": {"start_time": "올바른 시간 형식이 아닙니다 (예: 10:00 또는 2026-01-15 10:00)"}}
        if end_time is None:
            return {"errors": {"end_time": "올바른 시간 형식이 아닙니다 (예: 18:00 또는 2026-01-15 18:00)"}}
        
        # Validate
        validation_result = self.validator.validate(
            iam_user_name=iam_user_name,
            env=env,
            service=service,
            start_time=start_time,
            end_time=end_time,
            purpose=purpose,
            is_master_request=is_master,
        )
        
        if not validation_result.is_valid:
            # Return first error for dialog
            for error in validation_result.errors:
                return {"errors": {error.field: error.message}}
        
        # Validate IAM user exists
        iam_validation = self.validator.validate_iam_user_exists(iam_user_name)
        if not iam_validation.is_valid:
            for error in iam_validation.errors:
                return {"errors": {"iam_user_name": error.message}}
        
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
            "elasticbeanstalk": "ElasticBeanstalk",
        }
        
        # Create request - use target_user_id for master requests
        request = RoleRequest(
            request_id=str(uuid.uuid4()),
            requester_mattermost_id=target_user_id if is_master else user_id,
            requester_name=target_user_name if is_master else user_name,
            iam_user_name=iam_user_name,
            env=env,
            service=service,
            start_time=start_time,
            end_time=end_time,
            purpose=purpose,
            permission_type=permission_type,
            target_services=target_services,
            status=RequestStatus.APPROVED if is_master else RequestStatus.PENDING,
            approver_id=user_id if is_master else None,
            is_master_request=is_master,
            work_request_id=work_request_id,  # 업무 요청과 연결
        )
        
        # Save to repository
        if self.repository:
            self.repository.save(request)
        
        perm_display = permission_type_names.get(permission_type, permission_type)
        target_display = target_service_names.get(target_services_str, target_services_str)
        
        # For master request, immediately create role
        if is_master:
            return self._handle_master_dialog_submission(request, perm_display, target_display)
        
        # For normal request, forward to approval channel
        self._forward_to_approval_channel(request)
        
        # Send confirmation DM - ensure user_name is not empty
        dm_user_name = user_name
        if not dm_user_name and self.mattermost_client:
            try:
                user_info = self.mattermost_client.get_user_by_id(user_id)
                if user_info:
                    dm_user_name = user_info.get("username", user_id)
            except Exception as e:
                print(f"Failed to get username for DM: {e}")
                dm_user_name = user_id
        
        if self.mattermost_client:
            try:
                self.mattermost_client.send_dm(
                    user_id=user_id,
                    message=f"✅ 권한 요청이 제출되었습니다.\n\n"
                           f"**요청자 Mattermost ID:** {dm_user_name}\n"
                           f"**요청 ID:** {request.request_id}\n"
                           f"**IAM User:** {iam_user_name}\n"
                           f"**Env:** {env}\n"
                           f"**Service:** {service}\n"
                           f"**권한 유형:** {perm_display}\n"
                           f"**대상 서비스:** {target_display}\n"
                           f"**시작 시간:** {start_time.strftime('%Y-%m-%d %H:%M')} (KST)\n"
                           f"**종료 시간:** {end_time.strftime('%Y-%m-%d %H:%M')} (KST)\n\n"
                           f"담당자 승인 후 알림을 받으실 수 있습니다.",
                )
            except Exception as e:
                print(f"Failed to send confirmation DM: {e}")
        
        return {}
    
    def _handle_master_dialog_submission(
        self,
        request: RoleRequest,
        perm_display: str,
        target_display: str,
    ) -> Dict[str, Any]:
        """Handle master request dialog submission - immediately create role"""
        from services.role_manager import RoleManager
        from services.scheduler import Scheduler
        
        role_manager = self.role_manager or RoleManager()
        scheduler = self.scheduler or Scheduler()
        
        try:
            # Create role immediately
            role_info = role_manager.create_dynamic_role(request)
            request.role_arn = role_info.get("role_arn")
            request.policy_arn = role_info.get("policy_arn")
            request.status = RequestStatus.ACTIVE
            
            # Update in repository
            if self.repository:
                self.repository.update_status(
                    request.request_id,
                    RequestStatus.ACTIVE,
                    role_arn=request.role_arn,
                    policy_arn=request.policy_arn,
                )
            
            # Schedule deletion
            scheduler.create_end_schedule(request)
            
            # Send success DM
            if self.mattermost_client:
                role_name = request.role_arn.split("/")[-1]
                self.mattermost_client.send_dm(
                    user_id=request.requester_mattermost_id,
                    message=f"✅ AWS Role이 즉시 생성되었습니다! (관리자 즉시 부여)\n\n"
                           f"**요청 ID:** {request.request_id}\n"
                           f"**Role ARN:** {request.role_arn}\n\n"
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
                           f"CREDS=$(aws sts assume-role --role-arn {request.role_arn} --role-session-name {request.iam_user_name}-session --query 'Credentials' --output json)\n\n"
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
            
            return {}
            
        except Exception as e:
            print(f"[_handle_master_dialog_submission] Error: {e}")
            # Send error DM
            if self.mattermost_client:
                self.mattermost_client.send_dm(
                    user_id=request.requester_mattermost_id,
                    message=f"❌ Role 생성 중 오류가 발생했습니다.\n\n"
                           f"**요청 ID:** {request.request_id}\n"
                           f"**오류:** {str(e)}",
                )
            return {}
    
    def _parse_single_time(self, time_str: str) -> Optional[datetime]:
        """
        Parse a single time string (KST)
        
        Supports:
        - "10:00" (today)
        - "2026-01-15 10:00" (specific date)
        
        Returns:
            datetime in KST (naive) or None
        """
        now_kst = datetime.now(KST)
        today_kst = now_kst.date()
        
        # Try "HH:MM" format
        time_only_pattern = r"^(\d{1,2}):(\d{2})$"
        match = re.match(time_only_pattern, time_str.strip())
        if match:
            hour = int(match.group(1))
            minute = int(match.group(2))
            return datetime(today_kst.year, today_kst.month, today_kst.day, hour, minute)
        
        # Try "YYYY-MM-DD HH:MM" format
        full_pattern = r"^(\d{4}-\d{2}-\d{2})\s+(\d{1,2}):(\d{2})$"
        match = re.match(full_pattern, time_str.strip())
        if match:
            try:
                date_part = match.group(1)
                hour = int(match.group(2))
                minute = int(match.group(3))
                date = datetime.strptime(date_part, "%Y-%m-%d")
                return datetime(date.year, date.month, date.day, hour, minute)
            except ValueError:
                return None
        
        return None
    
    def handle_master_request(self, event: Dict[str, Any]) -> Dict[str, Any]:
        """
        Handle /master-request-role slash command (admin only)
        Opens interactive dialog for immediate role creation
        
        Args:
            event: Mattermost slash command event
        
        Returns:
            Response for Mattermost
        """
        user_id = event.get("user_id", "")
        trigger_id = event.get("trigger_id", "")
        
        # Check admin permission
        if not self.is_admin(user_id):
            return self._error_response("권한이 없습니다. 관리자만 사용할 수 있습니다.")
        
        # Open interactive dialog for master request
        if trigger_id and self.mattermost_client:
            try:
                # Get all users for dropdown
                users = self.mattermost_client.get_all_users()
                user_options = [
                    {
                        "text": f"{u.get('username', '')} ({u.get('first_name', '')} {u.get('last_name', '')})",
                        "value": u.get("id", ""),
                    }
                    for u in users
                ]
                
                dialog = create_request_dialog(is_master=True, user_options=user_options)
                self.mattermost_client.open_dialog(
                    trigger_id=trigger_id,
                    url=self.callback_url.replace("/interactive", "/dialog"),
                    dialog=dialog,
                )
                return {"response_type": "ephemeral", "text": ""}
            except Exception as e:
                print(f"Failed to open master dialog: {e}")
                return self._error_response(f"다이얼로그를 열 수 없습니다: {str(e)}")
        
        return self._error_response("다이얼로그를 열 수 없습니다. 다시 시도해주세요.")
    
    def _parse_request_text(
        self,
        text: str,
        allow_past_start: bool = False,
    ) -> Optional[Tuple[str, str, str, datetime, datetime, str]]:
        """
        Parse request text into components
        
        Args:
            text: Request text from user
            allow_past_start: If True, allow start time in past
        
        Returns:
            Tuple of (iam_user_name, env, service, start_time, end_time, purpose)
            or None if parsing fails
        """
        # Pattern for parsing the request
        patterns = {
            "iam_user_name": r"IAM\s*user\s*명?\s*:\s*(.+)",
            "env": r"Env\s*:\s*(\w+)",
            "service": r"Service\s*:\s*([\w-]+)",
            "time": r"시간\s*:\s*(.+)",
            "purpose": r"목적\s*:\s*(.+)",
        }
        
        results = {}
        for key, pattern in patterns.items():
            match = re.search(pattern, text, re.IGNORECASE | re.MULTILINE)
            if match:
                results[key] = match.group(1).strip()
        
        # Check all required fields
        required = ["iam_user_name", "env", "service", "time", "purpose"]
        if not all(key in results for key in required):
            return None
        
        # Parse time
        time_str = results["time"]
        start_time, end_time = self._parse_time_string(time_str)
        if start_time is None or end_time is None:
            return None
        
        return (
            results["iam_user_name"],
            results["env"],
            results["service"],
            start_time,
            end_time,
            results["purpose"],
        )
    
    def _parse_time_string(
        self,
        time_str: str,
    ) -> Tuple[Optional[datetime], Optional[datetime]]:
        """
        Parse time string into start and end datetime (KST input, KST output - naive)
        
        Supports formats:
        - "09-18시" or "09:00-18:00" (today in KST)
        - "2025-01-15 09:00 ~ 2025-01-15 18:00" (KST)
        
        Returns:
            Tuple of (start_time, end_time) as naive datetime in KST
        """
        # Get current time in KST
        now_kst = datetime.now(KST)
        today_kst = now_kst.date()
        
        # Try format: "09-18시" or "09:00-18:00"
        simple_pattern = r"(\d{1,2})(?::(\d{2}))?[-~](\d{1,2})(?::(\d{2}))?시?"
        match = re.match(simple_pattern, time_str.strip())
        if match:
            start_hour = int(match.group(1))
            start_min = int(match.group(2) or 0)
            end_hour = int(match.group(3))
            end_min = int(match.group(4) or 0)
            
            # Create naive datetime (representing KST)
            start_time = datetime(
                today_kst.year, today_kst.month, today_kst.day,
                start_hour, start_min
            )
            end_time = datetime(
                today_kst.year, today_kst.month, today_kst.day,
                end_hour, end_min
            )
            
            # If end time is before start time, assume next day
            if end_time <= start_time:
                end_time += timedelta(days=1)
            
            return start_time, end_time
        
        # Try format: "2025-01-15 09:00 ~ 2025-01-15 18:00"
        full_pattern = r"(\d{4}-\d{2}-\d{2})\s+(\d{2}:\d{2})\s*[~-]\s*(\d{4}-\d{2}-\d{2})\s+(\d{2}:\d{2})"
        match = re.match(full_pattern, time_str.strip())
        if match:
            try:
                # Parse as naive datetime (representing KST)
                start_time = datetime.strptime(
                    f"{match.group(1)} {match.group(2)}", "%Y-%m-%d %H:%M"
                )
                end_time = datetime.strptime(
                    f"{match.group(3)} {match.group(4)}", "%Y-%m-%d %H:%M"
                )
                
                return start_time, end_time
            except ValueError:
                return None, None
        
        return None, None
    
    def _forward_to_approval_channel(self, request: RoleRequest) -> None:
        """Forward request to approval channel"""
        # Get target_services as string for display
        target_services_str = request.target_services[0] if request.target_services else "all"
        
        # Get requester username - ensure it's not empty
        requester_name = request.requester_name
        if not requester_name and request.requester_mattermost_id and self.mattermost_client:
            try:
                user_info = self.mattermost_client.get_user_by_id(request.requester_mattermost_id)
                if user_info:
                    requester_name = user_info.get("username", request.requester_mattermost_id)
            except Exception as e:
                print(f"[_forward_to_approval_channel] Failed to get username: {e}")
                requester_name = request.requester_mattermost_id
        
        if not requester_name:
            requester_name = request.requester_mattermost_id or "Unknown"
        
        attachment = create_approval_message(
            request_id=request.request_id,
            requester_name=requester_name,
            iam_user_name=request.iam_user_name,
            env=request.env,
            service=request.service,
            start_time=request.start_time.strftime("%Y-%m-%d %H:%M"),
            end_time=request.end_time.strftime("%Y-%m-%d %H:%M"),
            purpose=request.purpose,
            callback_url=self.callback_url,
            permission_type=request.permission_type,
            target_services=target_services_str,
        )
        
        response = self.mattermost_client.send_interactive_message(
            channel_id=APPROVAL_CHANNEL_ID,
            text=f"📋 새로운 권한 요청이 도착했습니다.",
            attachments=[attachment],
        )
        
        # Update request with post_id
        if self.repository and "id" in response:
            request.post_id = response["id"]
            self.repository.update_post_id(request.request_id, response["id"])
        
        # Send request log to request channel (global_aws_request) for history tracking
        if REQUEST_CHANNEL_ID:
            try:
                now_kst = datetime.now(KST)
                self.mattermost_client.send_to_channel(
                    channel_id=REQUEST_CHANNEL_ID,
                    message=f"📝 **{requester_name}** 유저가 권한을 요청했습니다.\n"
                           f"- 요청 ID: `{request.request_id}`\n"
                           f"- IAM User: `{request.iam_user_name}`\n"
                           f"- Env: `{request.env}` | Service: `{request.service}`\n"
                           f"- 시간: {request.start_time.strftime('%Y-%m-%d %H:%M')} ~ {request.end_time.strftime('%Y-%m-%d %H:%M')} (KST)\n"
                           f"- 요청 시각: {now_kst.strftime('%Y-%m-%d %H:%M:%S')} (KST)",
                )
            except Exception as e:
                print(f"[_forward_to_approval_channel] Failed to send to request channel: {e}")
    
    def _response(self, text: str) -> Dict[str, Any]:
        """Create a response"""
        return {
            "response_type": "ephemeral",
            "text": text,
        }
    
    def _error_response(self, text: str) -> Dict[str, Any]:
        """Create an error response"""
        return {
            "response_type": "ephemeral",
            "text": f"❌ {text}",
        }


def lambda_handler(event: Dict[str, Any], context: Any) -> Dict[str, Any]:
    """Lambda handler for slash commands and dialog submissions"""
    
    # Extract API Gateway URL from event for callback
    request_context = event.get("requestContext", {})
    domain_name = request_context.get("domainName", "")
    stage = request_context.get("stage", "prod")
    path = request_context.get("path", "")
    callback_url = f"https://{domain_name}/{stage}/interactive" if domain_name else ""
    
    # Initialize services
    from services.dynamodb_repository import RoleRequestRepository
    table_name = os.environ.get("DYNAMODB_TABLE", "RoleRequests")
    repository = RoleRequestRepository(table_name=table_name)
    
    handler = RequestHandler(
        callback_url=callback_url,
        repository=repository,
    )
    
    # Parse the body
    body = event.get("body", "")
    if isinstance(body, str):
        # Try JSON first (for dialog submissions)
        try:
            params = json.loads(body)
        except json.JSONDecodeError:
            # URL-encoded form data (for slash commands)
            import urllib.parse
            params = dict(urllib.parse.parse_qsl(body))
    else:
        params = body
    
    print(f"[lambda_handler] path: {path}")
    print(f"[lambda_handler] params: {json.dumps(params)}")
    
    # Check if this is a dialog submission
    if path.endswith("/dialog") or "callback_id" in params:
        result = handler.handle_dialog_submission(params)
        return {
            "statusCode": 200,
            "headers": {"Content-Type": "application/json"},
            "body": json.dumps(result),
        }
    
    # Handle slash commands
    command = params.get("command", "")
    
    if command == "/request-role":
        result = handler.handle_slash_command(params)
    elif command == "/master-request-role":
        result = handler.handle_master_request(params)
    else:
        result = {"response_type": "ephemeral", "text": "Unknown command"}
    
    return {
        "statusCode": 200,
        "headers": {"Content-Type": "application/json"},
        "body": json.dumps(result),
    }
