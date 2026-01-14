"""
EventBridge Scheduler Service for AWS Role Request System
"""
import os
import boto3
from datetime import datetime
from typing import Optional

from models import RoleRequest


class Scheduler:
    """Manages EventBridge schedules for role creation/deletion"""
    
    def __init__(
        self,
        scheduler_client=None,
        lambda_arn: Optional[str] = None,
        scheduler_role_arn: Optional[str] = None,
    ):
        self.scheduler_client = scheduler_client or boto3.client("scheduler")
        self.lambda_arn = lambda_arn or os.environ.get("ROLE_MANAGER_LAMBDA_ARN", "")
        self.scheduler_role_arn = scheduler_role_arn or os.environ.get("SCHEDULER_ROLE_ARN", "")
    
    def create_start_schedule(self, request: RoleRequest) -> str:
        """
        Create schedule for role creation at start_time
        
        Args:
            request: Role request
        
        Returns:
            Schedule name
        """
        schedule_name = f"role-create-{request.request_id}"
        
        schedule_params = {
            "Name": schedule_name,
            "ScheduleExpression": f"at({request.start_time.strftime('%Y-%m-%dT%H:%M:%S')})",
            "ScheduleExpressionTimezone": "Asia/Seoul",
            "Target": {
                "Arn": self.lambda_arn,
                "RoleArn": self.scheduler_role_arn,
                "Input": f'{{"action": "create_role", "request_id": "{request.request_id}"}}',
            },
            "FlexibleTimeWindow": {"Mode": "OFF"},
        }
        
        try:
            self.scheduler_client.create_schedule(**schedule_params)
        except self.scheduler_client.exceptions.ConflictException:
            # Schedule already exists, update it
            self.scheduler_client.update_schedule(**schedule_params)
        
        return schedule_name
    
    def create_end_schedule(self, request: RoleRequest) -> str:
        """
        Create schedule for role deletion at end_time
        
        Args:
            request: Role request
        
        Returns:
            Schedule name
        """
        schedule_name = f"role-delete-{request.request_id}"
        
        schedule_params = {
            "Name": schedule_name,
            "ScheduleExpression": f"at({request.end_time.strftime('%Y-%m-%dT%H:%M:%S')})",
            "ScheduleExpressionTimezone": "Asia/Seoul",
            "Target": {
                "Arn": self.lambda_arn,
                "RoleArn": self.scheduler_role_arn,
                "Input": f'{{"action": "delete_role", "request_id": "{request.request_id}"}}',
            },
            "FlexibleTimeWindow": {"Mode": "OFF"},
        }
        
        try:
            self.scheduler_client.create_schedule(**schedule_params)
        except self.scheduler_client.exceptions.ConflictException:
            # Schedule already exists, update it
            self.scheduler_client.update_schedule(**schedule_params)
        
        return schedule_name
    
    def delete_schedule(self, schedule_name: str) -> None:
        """
        Delete a schedule
        
        Args:
            schedule_name: Name of the schedule to delete
        """
        try:
            self.scheduler_client.delete_schedule(Name=schedule_name)
        except self.scheduler_client.exceptions.ResourceNotFoundException:
            pass  # Already deleted
