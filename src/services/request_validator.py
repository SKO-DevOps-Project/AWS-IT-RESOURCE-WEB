"""
Request validation service for AWS Role Request System
"""
from datetime import datetime, timedelta, timezone
from typing import Optional
import boto3
from botocore.exceptions import ClientError

from models import (
    ValidationResult,
    VALID_ENVS,
    VALID_SERVICES,
)

# Korea Standard Time (UTC+9)
KST = timezone(timedelta(hours=9))


class RequestValidator:
    """Validates role request data"""
    
    MAX_DURATION_HOURS = 24
    
    def __init__(self, iam_client=None):
        self.iam_client = iam_client or boto3.client("iam")
    
    def validate(
        self,
        iam_user_name: Optional[str],
        env: Optional[str],
        service: Optional[str],
        start_time: Optional[datetime],
        end_time: Optional[datetime],
        purpose: Optional[str],
        is_master_request: bool = False,
        current_time: Optional[datetime] = None,
    ) -> ValidationResult:
        """
        Validate all request fields
        
        Args:
            iam_user_name: AWS IAM user name
            env: Environment (prod, test, infra, staging, dev)
            service: Service name
            start_time: Requested start time (KST, naive)
            end_time: Requested end time (KST, naive)
            purpose: Purpose of the request
            is_master_request: If True, allows start_time in past (sets to now)
            current_time: Current time for testing (defaults to KST now)
        
        Returns:
            ValidationResult with is_valid and errors
        """
        result = ValidationResult(is_valid=True)
        # Use KST for current time (naive datetime)
        if current_time is None:
            current_time = datetime.now(KST).replace(tzinfo=None)
        
        # Required field validation
        self._validate_required_fields(
            result, iam_user_name, env, service, start_time, end_time, purpose
        )
        
        if not result.is_valid:
            return result
        
        # Enum validation
        self._validate_env(result, env)
        self._validate_service(result, service)
        
        # Time validation
        self._validate_time(result, start_time, end_time, is_master_request, current_time)
        
        return result
    
    def _validate_required_fields(
        self,
        result: ValidationResult,
        iam_user_name: Optional[str],
        env: Optional[str],
        service: Optional[str],
        start_time: Optional[datetime],
        end_time: Optional[datetime],
        purpose: Optional[str],
    ) -> None:
        """Validate all required fields are present and non-empty"""
        fields = {
            "iam_user_name": iam_user_name,
            "env": env,
            "service": service,
            "start_time": start_time,
            "end_time": end_time,
            "purpose": purpose,
        }
        
        for field_name, value in fields.items():
            if value is None:
                result.add_error(field_name, f"필수 항목 '{field_name}'이(가) 누락되었습니다")
            elif isinstance(value, str) and not value.strip():
                result.add_error(field_name, f"필수 항목 '{field_name}'이(가) 비어있습니다")
    
    def _validate_env(self, result: ValidationResult, env: str) -> None:
        """Validate env is one of valid options"""
        if env and env not in VALID_ENVS:
            result.add_error(
                "env",
                f"유효하지 않은 Env입니다. ({', '.join(VALID_ENVS)} 중 선택)"
            )
    
    def _validate_service(self, result: ValidationResult, service: str) -> None:
        """Validate service is one of valid options"""
        if service and service not in VALID_SERVICES:
            result.add_error(
                "service",
                f"유효하지 않은 Service입니다."
            )
    
    def _validate_time(
        self,
        result: ValidationResult,
        start_time: datetime,
        end_time: datetime,
        is_master_request: bool,
        current_time: datetime,
    ) -> None:
        """Validate time constraints"""
        if not start_time or not end_time:
            return
        
        # Check start_time is not too far in the past (allow 1 minute tolerance for immediate start)
        # This allows "즉시 시작" where start_time is set to current time
        one_minute_ago = current_time - timedelta(minutes=1)
        if start_time < one_minute_ago:
            result.add_error(
                "start_time",
                "시작 시간은 현재 시간 이후여야 합니다"
            )
        
        # Check end_time is after start_time
        if end_time <= start_time:
            result.add_error(
                "end_time",
                "종료 시간은 시작 시간 이후여야 합니다"
            )
        
        # Check duration does not exceed 24 hours
        duration = end_time - start_time
        max_duration = timedelta(hours=self.MAX_DURATION_HOURS)
        if duration > max_duration:
            result.add_error(
                "end_time",
                f"최대 요청 가능 시간은 {self.MAX_DURATION_HOURS}시간입니다"
            )
    
    def validate_iam_user_exists(self, iam_user_name: str) -> ValidationResult:
        """
        Validate IAM user exists in AWS
        
        Args:
            iam_user_name: AWS IAM user name to check
        
        Returns:
            ValidationResult
        """
        result = ValidationResult(is_valid=True)
        
        try:
            self.iam_client.get_user(UserName=iam_user_name)
        except ClientError as e:
            if e.response["Error"]["Code"] == "NoSuchEntity":
                result.add_error(
                    "iam_user_name",
                    f"IAM 사용자 '{iam_user_name}'을(를) 찾을 수 없습니다"
                )
            else:
                result.add_error(
                    "iam_user_name",
                    f"IAM 사용자 확인 중 오류가 발생했습니다: {e}"
                )
        
        return result
