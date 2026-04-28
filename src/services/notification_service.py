"""
Centralized Mattermost notification service for AWS Role Request System.
All notification logic lives here — handlers call these functions instead of
building messages inline.
"""
import os
import re
from datetime import datetime
from typing import Optional, List, Union

from services.mattermost_client import (
    MattermostClient,
    Attachment,
    Action,
    create_approval_message,
)

# ──────────────────── Display Constants ────────────────────

PERMISSION_TYPE_DISPLAY = {
    "read_only": "조회만",
    "read_update": "조회+수정",
    "read_update_create": "조회+수정+생성",
    "full": "전체(삭제포함)",
}

TARGET_SERVICE_DISPLAY = {
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
    "billing": "Billing (비용 조회)",
    "ecr": "ECR",
    "eks": "EKS",
    "bedrock": "Bedrock",
}


def get_permission_display(permission_type: str) -> str:
    return PERMISSION_TYPE_DISPLAY.get(permission_type, permission_type)


def get_target_services_display(target_services: Union[str, List[str]]) -> str:
    if isinstance(target_services, list):
        return ", ".join(TARGET_SERVICE_DISPLAY.get(s, s) for s in target_services)
    return TARGET_SERVICE_DISPLAY.get(target_services, target_services)


# ──────────────────── Smart DM (bug-fix core) ────────────────────

_MATTERMOST_ID_PATTERN = re.compile(r'^[a-z0-9]{26}$')


def _smart_send_dm(
    mattermost: MattermostClient,
    requester_mattermost_id: str,
    message: str,
) -> bool:
    """
    Send DM using the appropriate method based on the id format.
    - Mattermost user_id (26-char lowercase alnum) → send_dm(user_id=...)
    - Otherwise treat as username → send_dm_by_username(username=...)
    Falls back to the other method if the first one fails.

    Returns True if DM was sent successfully.
    """
    if not requester_mattermost_id:
        print("[_smart_send_dm] No requester_mattermost_id, skipping DM")
        return False

    is_user_id = bool(_MATTERMOST_ID_PATTERN.match(requester_mattermost_id))

    try:
        if is_user_id:
            mattermost.send_dm(user_id=requester_mattermost_id, message=message)
        else:
            mattermost.send_dm_by_username(username=requester_mattermost_id, message=message)
        return True
    except Exception as primary_err:
        print(f"[_smart_send_dm] Primary method failed: {primary_err}")

    # Fallback to the other method
    try:
        if is_user_id:
            mattermost.send_dm_by_username(username=requester_mattermost_id, message=message)
        else:
            mattermost.send_dm(user_id=requester_mattermost_id, message=message)
        return True
    except Exception as fallback_err:
        print(f"[_smart_send_dm] Fallback also failed: {fallback_err}")
        return False


# ──────────────────── Channel update helper ────────────────────

def _update_or_send_to_channel(
    mattermost: MattermostClient,
    channel_id: str,
    message: str,
    attachment: Attachment,
    post_id: Optional[str] = None,
):
    """Try to update an existing post; if that fails send a new message."""
    if post_id:
        try:
            mattermost.update_message(
                post_id=post_id,
                message=message,
                attachments=[attachment],
            )
            return
        except Exception as e:
            print(f"[_update_or_send_to_channel] Update failed: {e}")
    if channel_id:
        mattermost.send_to_channel(
            channel_id=channel_id,
            message=message,
            attachments=[attachment],
        )


# ──────────────────── Message builders ────────────────────

def _build_role_created_dm(
    request_id: str,
    role_arn: str,
    iam_user_name: str,
    env: str,
    service: str,
    start_time_str: str,
    end_time_str: str,
    perm_display: str,
    target_display: str,
    source: str = "",
) -> str:
    role_name = role_arn.split("/")[-1]
    source_tag = f" ({source})" if source else ""

    return (
        f"✅ AWS Role이 생성되었습니다!{source_tag}\n\n"
        f"**요청 ID:** {request_id}\n"
        f"**Role ARN:** {role_arn}\n\n"
        f"---\n"
        f"## 🖥️ Console에서 사용하기 (Switch Role)\n"
        f"1. AWS Console 우측 상단 → Switch Role\n"
        f"2. Account: `680877507363`\n"
        f"3. Role: `{role_name}`\n\n"
        f"---\n"
        f"## 💻 CLI에서 사용하기\n\n"
        f"**방법 1: 환경변수 설정 - Mac/Linux**\n"
        f"```bash\n"
        f"# 1. assume-role 실행\n"
        f"CREDS=$(aws sts assume-role --role-arn {role_arn} --role-session-name {iam_user_name}-session --query 'Credentials' --output json)\n\n"
        f"# 2. 환경변수 설정\n"
        f"export AWS_ACCESS_KEY_ID=$(echo $CREDS | jq -r '.AccessKeyId')\n"
        f"export AWS_SECRET_ACCESS_KEY=$(echo $CREDS | jq -r '.SecretAccessKey')\n"
        f"export AWS_SESSION_TOKEN=$(echo $CREDS | jq -r '.SessionToken')\n\n"
        f"# 3. 확인\n"
        f"aws sts get-caller-identity\n"
        f"```\n\n"
        f"**방법 2: 환경변수 설정 - Windows (PowerShell)**\n"
        f"```powershell\n"
        f"# 1. assume-role 실행\n"
        f'$creds = (aws sts assume-role --role-arn {role_arn} --role-session-name {iam_user_name}-session --query "Credentials" --output json) | ConvertFrom-Json\n\n'
        f"# 2. 환경변수 설정\n"
        f"$env:AWS_ACCESS_KEY_ID = $creds.AccessKeyId\n"
        f"$env:AWS_SECRET_ACCESS_KEY = $creds.SecretAccessKey\n"
        f"$env:AWS_SESSION_TOKEN = $creds.SessionToken\n\n"
        f"# 3. 확인\n"
        f"aws sts get-caller-identity\n"
        f"```\n\n"
        f"**방법 3: AWS Profile 설정 (모든 OS)**\n"
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
        f"**시작 시간:** {start_time_str} (KST)\n"
        f"**종료 시간:** {end_time_str} (KST)\n"
        f"**Env:** {env} | **Service:** {service}\n"
        f"**권한 유형:** {perm_display} | **대상 서비스:** {target_display}"
    )


def _build_extras_message(
    include_parameter_store: bool,
    include_secrets_manager: bool,
) -> Optional[str]:
    extras = []
    if include_parameter_store:
        extras.append("Parameter Store")
    if include_secrets_manager:
        extras.append("Secrets Manager")
    if extras:
        return f"**추가 권한:** {' + '.join(extras)} (읽기전용)"
    return None


# ──────────────────── Public notification functions ────────────────────

def notify_request_created(
    mattermost: MattermostClient,
    request_id: str,
    requester_name: str,
    requester_mattermost_id: str,
    iam_user_name: str,
    env: str,
    service: str,
    start_time: datetime,
    end_time: datetime,
    purpose: str,
    permission_type: str,
    target_services: Union[str, List[str]],
    callback_url: str,
    source: str = "",
    include_parameter_store: bool = False,
    include_secrets_manager: bool = False,
) -> Optional[str]:
    """
    Send request-created notifications.
    1) Approval card → APPROVAL channel
    2) Text log → REQUEST channel
    3) Confirmation DM → requester

    Returns the post_id of the approval card (or None).
    """
    approval_channel_id = os.environ.get("APPROVAL_CHANNEL_ID", "")
    request_channel_id = os.environ.get("REQUEST_CHANNEL_ID", "")

    start_str = start_time.strftime("%Y-%m-%d %H:%M")
    end_str = end_time.strftime("%Y-%m-%d %H:%M")
    source_tag = f" ({source})" if source else ""

    post_id = None

    # 1) Approval card
    if approval_channel_id:
        try:
            attachment = create_approval_message(
                request_id=request_id,
                requester_name=requester_name,
                iam_user_name=iam_user_name,
                env=env,
                service=service,
                start_time=start_str,
                end_time=end_str,
                purpose=purpose,
                callback_url=callback_url,
                permission_type=permission_type,
                target_services=target_services,
                include_parameter_store=include_parameter_store,
                include_secrets_manager=include_secrets_manager,
            )
            resp = mattermost.send_interactive_message(
                channel_id=approval_channel_id,
                text=f"📋 새로운 권한 요청이 도착했습니다.{source_tag}",
                attachments=[attachment],
            )
            post_id = resp.get("id")
        except Exception as e:
            print(f"[notify_request_created] Approval card failed: {e}")

    # 2) Text log to REQUEST channel
    if request_channel_id:
        try:
            from datetime import timezone, timedelta
            KST = timezone(timedelta(hours=9))
            now_kst = datetime.now(KST)
            mattermost.send_to_channel(
                channel_id=request_channel_id,
                message=(
                    f"📝 **{requester_name or iam_user_name}** 유저가 권한을 요청했습니다.{source_tag}\n"
                    f"- 요청 ID: `{request_id}`\n"
                    f"- IAM User: `{iam_user_name}`\n"
                    f"- Env: `{env}` | Service: `{service}`\n"
                    f"- 시간: {start_str} ~ {end_str} (KST)\n"
                    f"- 요청 시각: {now_kst.strftime('%Y-%m-%d %H:%M:%S')} (KST)"
                ),
            )
        except Exception as e:
            print(f"[notify_request_created] Request channel failed: {e}")

    # 3) Confirmation DM
    if requester_mattermost_id:
        try:
            _smart_send_dm(
                mattermost,
                requester_mattermost_id,
                f"✅ 권한 요청이 제출되었습니다.\n\n"
                f"**요청 ID:** {request_id}\n"
                f"**IAM User:** {iam_user_name}\n"
                f"**Env:** {env}\n"
                f"**Service:** {service}\n"
                f"**시작 시간:** {start_str} (KST)\n"
                f"**종료 시간:** {end_str} (KST)\n\n"
                f"담당자 승인 후 알림을 받으실 수 있습니다.",
            )
        except Exception as e:
            print(f"[notify_request_created] DM failed: {e}")

    return post_id


def notify_approved(
    mattermost: MattermostClient,
    request_id: str,
    requester_name: str,
    requester_mattermost_id: str,
    iam_user_name: str,
    env: str,
    service: str,
    start_time_str: str,
    end_time_str: str,
    approver_name: str,
    permission_type: str = "read_update",
    target_services: Union[str, List[str]] = "all",
    role_arn: Optional[str] = None,
    callback_url: str = "",
    post_id: Optional[str] = None,
    is_scheduled: bool = False,
    source: str = "",
    include_parameter_store: bool = False,
    include_secrets_manager: bool = False,
):
    """
    Send approval notifications.
    1) Update/send approval channel card (green, with revoke button)
    2) DM to requester: role usage instructions (if immediate) or schedule info
    """
    approval_channel_id = os.environ.get("APPROVAL_CHANNEL_ID", "")
    perm_display = get_permission_display(permission_type)
    target_display = get_target_services_display(target_services)
    source_tag = f" ({source})" if source else ""

    # 1) Approval channel card
    if approval_channel_id:
        try:
            title_suffix = "/예약" if is_scheduled else ""
            title = f"✅ 승인됨{source_tag}{title_suffix}"

            text = (
                f"**요청자:** {requester_name}\n"
                f"**IAM User:** {iam_user_name}\n"
                f"**Env:** {env} | **Service:** {service}\n"
                f"**시간:** {start_time_str} ~ {end_time_str} (KST)\n\n"
                f"**승인자:** {approver_name}\n"
                f"**요청 ID:** {request_id}"
            )
            if is_scheduled:
                text += "\n시작 시간에 Role이 자동 생성됩니다."

            actions = []
            if callback_url:
                actions = [
                    Action(
                        id="revoke",
                        name="🔄 권한 회수",
                        integration={
                            "url": callback_url,
                            "context": {"action": "revoke", "request_id": request_id},
                        },
                        style="danger",
                    ),
                ]

            attachment = Attachment(
                fallback=f"승인됨: {requester_name}",
                color="#00FF00",
                title=title,
                text=text,
                actions=actions,
            )
            msg = f"📋 권한 요청 - 승인됨{source_tag}"
            _update_or_send_to_channel(mattermost, approval_channel_id, msg, attachment, post_id)
        except Exception as e:
            print(f"[notify_approved] Approval channel failed: {e}")

    # 2) DM to requester
    if requester_mattermost_id:
        try:
            if is_scheduled:
                dm_msg = (
                    f"✅ 권한 요청이 승인되었습니다.{source_tag}\n\n"
                    f"**요청 ID:** {request_id}\n"
                    f"**시작 시간:** {start_time_str} (KST)\n"
                    f"**종료 시간:** {end_time_str} (KST)\n\n"
                    f"시작 시간에 Role이 자동으로 생성됩니다."
                )
            else:
                dm_msg = _build_role_created_dm(
                    request_id=request_id,
                    role_arn=role_arn or "",
                    iam_user_name=iam_user_name,
                    env=env,
                    service=service,
                    start_time_str=start_time_str,
                    end_time_str=end_time_str,
                    perm_display=perm_display,
                    target_display=target_display,
                    source=source,
                )
            _smart_send_dm(mattermost, requester_mattermost_id, dm_msg)

            # Extra permissions
            extras_msg = _build_extras_message(include_parameter_store, include_secrets_manager)
            if extras_msg:
                _smart_send_dm(mattermost, requester_mattermost_id, extras_msg)
        except Exception as e:
            print(f"[notify_approved] DM failed: {e}")


def notify_rejected(
    mattermost: MattermostClient,
    request_id: str,
    requester_name: str,
    requester_mattermost_id: str,
    iam_user_name: str,
    env: str,
    service: str,
    rejecter_name: str,
    rejection_reason: str,
    post_id: Optional[str] = None,
    source: str = "",
):
    """
    Send rejection notifications.
    1) Update/send approval channel card (red)
    2) DM to requester
    """
    approval_channel_id = os.environ.get("APPROVAL_CHANNEL_ID", "")
    source_tag = f" ({source})" if source else ""

    # 1) Approval channel
    if approval_channel_id:
        try:
            attachment = Attachment(
                fallback=f"반려됨: {requester_name}",
                color="#FF0000",
                title=f"❌ 반려됨{source_tag}",
                text=(
                    f"**요청자:** {requester_name}\n"
                    f"**IAM User:** {iam_user_name}\n"
                    f"**Env:** {env} | **Service:** {service}\n\n"
                    f"**반려자:** {rejecter_name}\n"
                    f"**사유:** {rejection_reason}"
                ),
            )
            _update_or_send_to_channel(
                mattermost, approval_channel_id,
                f"📋 권한 요청 - 반려됨{source_tag}", attachment, post_id,
            )
        except Exception as e:
            print(f"[notify_rejected] Approval channel failed: {e}")

    # 2) DM
    if requester_mattermost_id:
        try:
            _smart_send_dm(
                mattermost,
                requester_mattermost_id,
                f"❌ 권한 요청이 반려되었습니다.{source_tag}\n\n"
                f"**요청 ID:** {request_id}\n"
                f"**반려 사유:** {rejection_reason}",
            )
        except Exception as e:
            print(f"[notify_rejected] DM failed: {e}")


def notify_revoked(
    mattermost: MattermostClient,
    request_id: str,
    requester_name: str,
    requester_mattermost_id: str,
    iam_user_name: str,
    env: str,
    service: str,
    revoker_name: str,
    post_id: Optional[str] = None,
    source: str = "",
):
    """
    Send revocation notifications.
    1) Update/send approval channel card (red)
    2) DM to requester
    """
    approval_channel_id = os.environ.get("APPROVAL_CHANNEL_ID", "")
    source_tag = f" ({source})" if source else ""

    # 1) Approval channel
    if approval_channel_id:
        try:
            attachment = Attachment(
                fallback=f"권한 회수됨: {requester_name}",
                color="#FF0000",
                title=f"🔄 권한이 회수되었습니다{source_tag}",
                text=(
                    f"**요청자:** {requester_name}\n"
                    f"**IAM User:** {iam_user_name}\n"
                    f"**Env:** {env} | **Service:** {service}\n\n"
                    f"**회수자:** {revoker_name}\n"
                    f"**요청 ID:** {request_id}"
                ),
            )
            _update_or_send_to_channel(
                mattermost, approval_channel_id,
                f"📋 권한 요청 - 권한 회수됨{source_tag}", attachment, post_id,
            )
        except Exception as e:
            print(f"[notify_revoked] Approval channel failed: {e}")

    # 2) DM
    if requester_mattermost_id:
        try:
            _smart_send_dm(
                mattermost,
                requester_mattermost_id,
                f"🔄 AWS Role 권한이 관리자에 의해 회수되었습니다.{source_tag}\n\n"
                f"**요청 ID:** {request_id}\n"
                f"**Env:** {env}\n"
                f"**Service:** {service}\n\n"
                f"문의사항이 있으시면 관리자에게 연락해주세요.",
            )
        except Exception as e:
            print(f"[notify_revoked] DM failed: {e}")


def notify_role_created(
    mattermost: MattermostClient,
    request_id: str,
    requester_mattermost_id: str,
    iam_user_name: str,
    env: str,
    service: str,
    start_time_str: str,
    end_time_str: str,
    role_arn: str,
    permission_type: str = "read_update",
    target_services: Union[str, List[str]] = "all",
    source: str = "",
    include_parameter_store: bool = False,
    include_secrets_manager: bool = False,
):
    """
    Send role-created DM (used by scheduled role creation & master request).
    """
    perm_display = get_permission_display(permission_type)
    target_display = get_target_services_display(target_services)

    dm_msg = _build_role_created_dm(
        request_id=request_id,
        role_arn=role_arn,
        iam_user_name=iam_user_name,
        env=env,
        service=service,
        start_time_str=start_time_str,
        end_time_str=end_time_str,
        perm_display=perm_display,
        target_display=target_display,
        source=source,
    )

    _smart_send_dm(mattermost, requester_mattermost_id, dm_msg)

    extras_msg = _build_extras_message(include_parameter_store, include_secrets_manager)
    if extras_msg:
        _smart_send_dm(mattermost, requester_mattermost_id, extras_msg)


def notify_role_expired(
    mattermost: MattermostClient,
    request_id: str,
    requester_mattermost_id: str,
    env: str,
    service: str,
):
    """Send role-expired DM."""
    _smart_send_dm(
        mattermost,
        requester_mattermost_id,
        f"🔒 AWS Role 권한이 만료되었습니다.\n\n"
        f"**요청 ID:** {request_id}\n"
        f"**Env:** {env}\n"
        f"**Service:** {service}\n\n"
        f"추가 권한이 필요하시면 다시 요청해주세요.",
    )
