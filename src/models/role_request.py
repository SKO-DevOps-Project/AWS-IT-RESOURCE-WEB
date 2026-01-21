"""
Data models for AWS Role Request System
"""
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Optional, List


class RequestStatus(Enum):
    """Status of a role request"""
    PENDING = "pending"      # 승인 대기
    APPROVED = "approved"    # 승인됨 (아직 시작 전)
    REJECTED = "rejected"    # 반려됨
    ACTIVE = "active"        # Role 활성화됨
    EXPIRED = "expired"      # 만료됨
    REVOKED = "revoked"      # 권한 회수됨
    ERROR = "error"          # 오류 발생


class PermissionType(Enum):
    """Permission type for role request"""
    READ_ONLY = "read_only"              # 조회만
    READ_UPDATE = "read_update"          # 조회 + 수정 (태그 기반)
    READ_UPDATE_CREATE = "read_update_create"  # 조회 + 수정 + 생성
    FULL = "full"                        # 전체 (삭제 포함, 태그 기반)


class TargetService(Enum):
    """Target AWS service for permissions"""
    EC2 = "ec2"
    RDS = "rds"
    LAMBDA = "lambda"
    S3 = "s3"
    ELASTICBEANSTALK = "elasticbeanstalk"
    ALL = "all"


# Valid environment values
VALID_ENVS = ["prod", "test", "infra", "staging", "dev"]

# Valid service values (business services) - used as AWS tags
VALID_SERVICES = [
    "aihub", "safety", "infra", "biz_drive", "alarm",
    "unit-mgnt", "software-updater", "sms-sender", "ai-nams",
    "fleet-mgnt", "bp-eval", "form-system", "sko-sso-auth",
    "sko-sftp", "asset-mgmt", "ocean", "security365"
]

# Display names for services (shown in Mattermost)
SERVICE_DISPLAY_NAMES = {
    "aihub": "ai-hub",
    "safety": "안전관리시스템",
    "infra": "인프라",
    "biz_drive": "전기차유지보수시스템",
    "alarm": "고장알람시스템",
    "unit-mgnt": "유니트관리시스템",
    "software-updater": "software-updater",
    "sms-sender": "sms전송시스템",
    "ai-nams": "ai-nams시스템",
    "fleet-mgnt": "차량예약시스템",
    "bp-eval": "BP사평가시스템",
    "form-system": "대리점지원시스템",
    "sko-sso-auth": "SSO인증시스템",
    "sko-sftp": "SKT-SKO SFTP시스템",
    "asset-mgmt": "TAMS관리시스템",
    "ocean": "OCEAN",
    "security365": "Security365",
}

# Valid permission types
VALID_PERMISSION_TYPES = [p.value for p in PermissionType]

# Valid target services
VALID_TARGET_SERVICES = [t.value for t in TargetService]


@dataclass
class ValidationError:
    """Validation error for a specific field"""
    field: str
    message: str


@dataclass
class ValidationResult:
    """Result of request validation"""
    is_valid: bool
    errors: List[ValidationError] = field(default_factory=list)
    
    def add_error(self, field: str, message: str) -> None:
        """Add a validation error"""
        self.errors.append(ValidationError(field=field, message=message))
        self.is_valid = False


@dataclass
class RoleRequest:
    """Role request data model"""
    request_id: str
    requester_mattermost_id: str
    requester_name: str
    iam_user_name: str
    env: str
    service: str
    start_time: datetime
    end_time: datetime
    purpose: str
    permission_type: str = "read_update"  # read_only, read_update, read_update_create, full
    target_services: List[str] = field(default_factory=lambda: ["all"])  # ec2, rds, lambda, s3, all
    status: RequestStatus = RequestStatus.PENDING
    created_at: datetime = field(default_factory=datetime.utcnow)
    updated_at: datetime = field(default_factory=datetime.utcnow)
    approver_id: Optional[str] = None
    rejection_reason: Optional[str] = None
    role_arn: Optional[str] = None
    policy_arn: Optional[str] = None
    post_id: Optional[str] = None
    is_master_request: bool = False
    
    def to_dict(self) -> dict:
        """Convert to dictionary for DynamoDB storage

        Note: None values are excluded to avoid DynamoDB GSI ValidationException.
        Items without GSI key attributes are simply not indexed (sparse index).
        """
        result = {
            "request_id": self.request_id,
            "requester_mattermost_id": self.requester_mattermost_id,
            "requester_name": self.requester_name,
            "iam_user_name": self.iam_user_name,
            "env": self.env,
            "service": self.service,
            "start_time": self.start_time.isoformat(),
            "end_time": self.end_time.isoformat(),
            "purpose": self.purpose,
            "permission_type": self.permission_type,
            "target_services": self.target_services,
            "status": self.status.value,
            "created_at": self.created_at.isoformat(),
            "updated_at": self.updated_at.isoformat(),
            "is_master_request": self.is_master_request,
        }

        # Optional fields - only include if not None
        if self.approver_id is not None:
            result["approver_id"] = self.approver_id
        if self.rejection_reason is not None:
            result["rejection_reason"] = self.rejection_reason
        if self.role_arn is not None:
            result["role_arn"] = self.role_arn
        if self.policy_arn is not None:
            result["policy_arn"] = self.policy_arn
        if self.post_id is not None:
            result["post_id"] = self.post_id

        return result
    
    @classmethod
    def from_dict(cls, data: dict) -> "RoleRequest":
        """Create from dictionary (DynamoDB record)"""
        return cls(
            request_id=data["request_id"],
            requester_mattermost_id=data["requester_mattermost_id"],
            requester_name=data["requester_name"],
            iam_user_name=data["iam_user_name"],
            env=data["env"],
            service=data["service"],
            start_time=datetime.fromisoformat(data["start_time"]),
            end_time=datetime.fromisoformat(data["end_time"]),
            purpose=data["purpose"],
            permission_type=data.get("permission_type", "read_update"),
            target_services=data.get("target_services", ["all"]),
            status=RequestStatus(data["status"]),
            created_at=datetime.fromisoformat(data["created_at"]),
            updated_at=datetime.fromisoformat(data["updated_at"]),
            approver_id=data.get("approver_id"),
            rejection_reason=data.get("rejection_reason"),
            role_arn=data.get("role_arn"),
            policy_arn=data.get("policy_arn"),
            post_id=data.get("post_id"),
            is_master_request=data.get("is_master_request", False),
        )
