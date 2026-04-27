"""
Mattermost API client for AWS Role Request System
"""
import os
import re
import requests
from typing import List, Dict, Any, Optional
from dataclasses import dataclass

# Mattermost user_id 형식: 26자 소문자 영숫자
_MATTERMOST_USER_ID_RE = re.compile(r'^[a-z0-9]{26}$')


@dataclass
class Action:
    """Mattermost button action"""
    id: str
    name: str
    integration: Dict[str, Any]
    style: str = "default"
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "name": self.name,
            "type": "button",
            "style": self.style,
            "integration": self.integration,
        }


@dataclass
class Attachment:
    """Mattermost message attachment"""
    fallback: str
    color: str = "#0076B4"
    pretext: str = ""
    text: str = ""
    author_name: str = ""
    title: str = ""
    fields: List[Dict[str, Any]] = None
    actions: List[Dict[str, Any]] = None
    
    def __post_init__(self):
        if self.fields is None:
            self.fields = []
        if self.actions is None:
            self.actions = []
    
    def to_dict(self) -> Dict[str, Any]:
        actions_list = []
        if self.actions:
            for a in self.actions:
                if hasattr(a, 'to_dict'):
                    actions_list.append(a.to_dict())
                else:
                    actions_list.append(a)
        
        return {
            "fallback": self.fallback,
            "color": self.color,
            "pretext": self.pretext,
            "text": self.text,
            "author_name": self.author_name,
            "title": self.title,
            "fields": self.fields,
            "actions": actions_list,
        }


@dataclass
class Dialog:
    """Mattermost interactive dialog"""
    callback_id: str
    title: str
    elements: List[Dict[str, Any]]
    submit_label: str = "Submit"
    notify_on_cancel: bool = False
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "callback_id": self.callback_id,
            "title": self.title,
            "elements": self.elements,
            "submit_label": self.submit_label,
            "notify_on_cancel": self.notify_on_cancel,
        }


class MattermostClient:
    """Client for Mattermost API interactions"""
    
    def __init__(
        self,
        base_url: Optional[str] = None,
        bot_token: Optional[str] = None,
    ):
        self.base_url = base_url or os.environ.get("MATTERMOST_URL", "")
        self.bot_token = bot_token or os.environ.get("MATTERMOST_BOT_TOKEN", "")
        self.headers = {
            "Authorization": f"Bearer {self.bot_token}",
            "Content-Type": "application/json",
        }
    
    def send_to_channel(
        self,
        channel_id: str,
        message: str,
        attachments: Optional[List[Attachment]] = None,
    ) -> Dict[str, Any]:
        """
        Send a message to a channel
        
        Args:
            channel_id: Mattermost channel ID
            message: Message text
            attachments: Optional list of attachments
        
        Returns:
            API response
        """
        payload = {
            "channel_id": channel_id,
            "message": message,
        }

        if attachments:
            payload["props"] = {
                "attachments": [a.to_dict() for a in attachments]
            }

        response = requests.post(
            f"{self.base_url}/api/v4/posts",
            headers=self.headers,
            json=payload,
        )
        response.raise_for_status()
        return response.json()
    
    def send_dm(self, user_id: str, message: str) -> Dict[str, Any]:
        """
        Send a direct message to a user.
        user_id가 26자 영숫자가 아니면 username으로 간주하고 자동 lookup.

        Args:
            user_id: Mattermost user ID (26자) 또는 username
            message: Message text

        Returns:
            API response
        """
        # 26자 영숫자 user_id 형식이 아니면 username으로 간주하여 lookup
        target_user_id = user_id
        if not _MATTERMOST_USER_ID_RE.match(user_id):
            print(f"[MattermostClient] '{user_id}' is not a user_id, looking up as username")
            user = self.get_user_by_username(user_id)
            if not user:
                raise ValueError(f"User not found by username: {user_id}")
            target_user_id = user["id"]
            print(f"[MattermostClient] Resolved username '{user_id}' → user_id '{target_user_id}'")

        # First, create or get the DM channel
        channel_response = requests.post(
            f"{self.base_url}/api/v4/channels/direct",
            headers=self.headers,
            json=[self._get_bot_user_id(), target_user_id],
        )
        channel_response.raise_for_status()
        channel_id = channel_response.json()["id"]

        # Then send the message
        return self.send_to_channel(channel_id, message)

    def send_dm_by_username(self, username: str, message: str) -> Optional[Dict[str, Any]]:
        """
        Send a direct message to a user by username

        Args:
            username: Mattermost username
            message: Message text

        Returns:
            API response or None if user not found
        """
        user = self.get_user_by_username(username)
        if not user:
            print(f"[MattermostClient] User not found: {username}")
            return None

        return self.send_dm(user["id"], message)

    def send_interactive_message(
        self,
        channel_id: str,
        text: str,
        attachments: List[Attachment],
    ) -> Dict[str, Any]:
        """
        Send an interactive message with buttons
        
        Args:
            channel_id: Mattermost channel ID
            text: Message text
            attachments: List of attachments with actions
        
        Returns:
            API response with post_id
        """
        return self.send_to_channel(channel_id, text, attachments)
    
    def update_message(
        self,
        post_id: str,
        message: str,
        attachments: Optional[List[Attachment]] = None,
    ) -> Dict[str, Any]:
        """
        Update an existing message
        
        Args:
            post_id: ID of the post to update
            message: New message text
            attachments: Optional new attachments
        
        Returns:
            API response
        """
        payload = {
            "id": post_id,
            "message": message,
        }
        
        if attachments:
            payload["props"] = {
                "attachments": [a.to_dict() for a in attachments]
            }
        
        response = requests.put(
            f"{self.base_url}/api/v4/posts/{post_id}",
            headers=self.headers,
            json=payload,
        )
        response.raise_for_status()
        return response.json()
    
    def open_dialog(
        self,
        trigger_id: str,
        dialog: Any,
        url: str,
    ) -> Dict[str, Any]:
        """
        Open an interactive dialog
        
        Args:
            trigger_id: Trigger ID from the interactive action
            dialog: Dialog configuration (Dialog object or dict)
            url: URL to submit the dialog to
        
        Returns:
            API response
        """
        dialog_dict = dialog.to_dict() if hasattr(dialog, 'to_dict') else dialog
        
        payload = {
            "trigger_id": trigger_id,
            "url": url,
            "dialog": dialog_dict,
        }
        
        response = requests.post(
            f"{self.base_url}/api/v4/actions/dialogs/open",
            headers=self.headers,
            json=payload,
        )
        response.raise_for_status()
        return response.json() if response.text else {}
    
    def _get_bot_user_id(self) -> str:
        """Get the bot's user ID"""
        response = requests.get(
            f"{self.base_url}/api/v4/users/me",
            headers=self.headers,
        )
        response.raise_for_status()
        return response.json()["id"]
    
    def get_user_by_username(self, username: str) -> Optional[Dict[str, Any]]:
        """
        Get user info by username
        
        Args:
            username: Mattermost username
        
        Returns:
            User info or None if not found
        """
        response = requests.get(
            f"{self.base_url}/api/v4/users/username/{username}",
            headers=self.headers,
        )
        if response.status_code == 404:
            return None
        response.raise_for_status()
        return response.json()
    
    def get_all_users(self, per_page: int = 200) -> List[Dict[str, Any]]:
        """
        Get all active users from Mattermost
        
        Args:
            per_page: Number of users per page
        
        Returns:
            List of user objects
        """
        all_users = []
        page = 0
        
        while True:
            response = requests.get(
                f"{self.base_url}/api/v4/users",
                headers=self.headers,
                params={
                    "page": page,
                    "per_page": per_page,
                    "active": True,  # Only active users
                },
            )
            response.raise_for_status()
            users = response.json()
            
            if not users:
                break
            
            # Filter out bots and deactivated users
            for user in users:
                if not user.get("is_bot", False) and user.get("delete_at", 0) == 0:
                    all_users.append(user)
            
            if len(users) < per_page:
                break
            
            page += 1
        
        # Sort by username
        all_users.sort(key=lambda u: u.get("username", ""))
        return all_users
    
    def get_user_by_id(self, user_id: str) -> Optional[Dict[str, Any]]:
        """
        Get user info by user ID
        
        Args:
            user_id: Mattermost user ID
        
        Returns:
            User info or None if not found
        """
        response = requests.get(
            f"{self.base_url}/api/v4/users/{user_id}",
            headers=self.headers,
        )
        if response.status_code == 404:
            return None
        response.raise_for_status()
        return response.json()


def create_approval_message(
    request_id: str,
    requester_name: str,
    iam_user_name: str,
    env: str,
    service: str,
    start_time: str,
    end_time: str,
    purpose: str,
    callback_url: str,
    permission_type: str = "read_update",
    target_services = "all",
    include_parameter_store: bool = False,
    include_secrets_manager: bool = False,
) -> Attachment:
    """
    Create an approval request message attachment
    
    Args:
        request_id: Unique request ID
        requester_name: Name of the requester
        iam_user_name: AWS IAM user name
        env: Environment
        service: Service name
        start_time: Formatted start time
        end_time: Formatted end time
        purpose: Purpose of the request
        callback_url: URL for button callbacks
        permission_type: Permission type (read_only, read_update, etc.)
        target_services: Target AWS services
    
    Returns:
        Attachment with approval/reject buttons
    """
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
        "dynamodb": "DynamoDB",
        "elasticloadbalancing": "ELB",
        "route53": "Route53",
        "amplify": "Amplify",
    }
    
    perm_display = permission_type_names.get(permission_type, permission_type)

    # target_services가 리스트로 올 수 있으므로 처리
    if isinstance(target_services, list):
        target_display = ", ".join(
            target_service_names.get(s, s) for s in target_services
        )
    else:
        target_display = target_service_names.get(target_services, target_services)

    fields = [
        {"short": True, "title": "요청자", "value": requester_name},
        {"short": True, "title": "IAM User", "value": iam_user_name},
        {"short": True, "title": "Environment", "value": env},
        {"short": True, "title": "Service", "value": service},
        {"short": True, "title": "권한 유형", "value": perm_display},
        {"short": True, "title": "대상 서비스", "value": target_display},
        {"short": True, "title": "시작 시간", "value": f"{start_time} (KST)"},
        {"short": True, "title": "종료 시간", "value": f"{end_time} (KST)"},
        {"short": False, "title": "목적", "value": purpose},
    ]

    extras = []
    if include_parameter_store: extras.append("Parameter Store")
    if include_secrets_manager: extras.append("Secrets Manager")
    if extras:
        fields.append({"short": True, "title": "추가 권한", "value": " + ".join(extras) + " (읽기전용)"})

    return Attachment(
        fallback=f"Role request from {requester_name}",
        color="#FFA500",
        title=f"🔐 AWS Role 권한 요청",
        fields=fields,
        actions=[
            {
                "id": "approve",
                "name": "승인",
                "type": "button",
                "style": "good",
                "integration": {
                    "url": callback_url,
                    "context": {
                        "action": "approve",
                        "request_id": request_id,
                    },
                },
            },
            {
                "id": "reject",
                "name": "반려",
                "type": "button",
                "style": "danger",
                "integration": {
                    "url": callback_url,
                    "context": {
                        "action": "reject",
                        "request_id": request_id,
                    },
                },
            },
        ],
    )


def create_work_request_notification(
    request_id: str,
    service_name: str,
    requester_name: str,
    start_date: str,
    end_date: str,
    description: str,
    callback_url: str,
) -> Attachment:
    """
    Create a work request notification attachment with button
    """
    return Attachment(
        fallback=f"새 업무 요청: {service_name}",
        color="#0076B4",
        title="📋 새 업무 요청이 등록되었습니다",
        fields=[
            {"short": True, "title": "서비스", "value": service_name},
            {"short": True, "title": "요청자", "value": requester_name},
            {"short": True, "title": "작업 시작일", "value": start_date},
            {"short": True, "title": "작업 종료일", "value": end_date},
            {"short": False, "title": "작업 내용", "value": description},
            {"short": False, "title": "요청 ID", "value": f"`{request_id}`"},
        ],
        actions=[
            {
                "id": "requestrole",
                "name": "권한 요청하기",
                "type": "button",
                "style": "primary",
                "integration": {
                    "url": callback_url,
                    "context": {
                        "action": "open_role_request_dialog",
                        "work_request_id": request_id,
                    },
                },
            },
        ],
    )


def create_rejection_dialog(request_id: str) -> Dialog:
    """
    Create a rejection reason dialog
    
    Args:
        request_id: Request ID for the callback
    
    Returns:
        Dialog for entering rejection reason
    """
    return Dialog(
        callback_id=f"reject_{request_id}",
        title="반려 사유 입력",
        submit_label="반려",
        elements=[
            {
                "display_name": "반려 사유",
                "name": "rejection_reason",
                "type": "textarea",
                "placeholder": "반려 사유를 입력해주세요",
                "optional": False,
            },
        ],
    )
