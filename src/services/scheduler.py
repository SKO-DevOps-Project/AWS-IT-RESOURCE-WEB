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

        # Validate required configuration
        if not self.lambda_arn:
            print("[Scheduler] WARNING: ROLE_MANAGER_LAMBDA_ARN is not configured")
        if not self.scheduler_role_arn:
            print("[Scheduler] WARNING: SCHEDULER_ROLE_ARN is not configured")
    
    def create_start_schedule(self, request: RoleRequest) -> str:
        """
        Create schedule for role creation at start_time

        Args:
            request: Role request

        Returns:
            Schedule name
        """
        schedule_name = f"role-create-{request.request_id}"
        schedule_expression = f"at({request.start_time.strftime('%Y-%m-%dT%H:%M:%S')})"

        print(f"[Scheduler] Creating start schedule: {schedule_name}")
        print(f"[Scheduler] Schedule expression: {schedule_expression} (Asia/Seoul)")
        print(f"[Scheduler] Target Lambda ARN: {self.lambda_arn}")
        print(f"[Scheduler] Scheduler Role ARN: {self.scheduler_role_arn}")

        schedule_params = {
            "Name": schedule_name,
            "ScheduleExpression": schedule_expression,
            "ScheduleExpressionTimezone": "Asia/Seoul",
            "State": "ENABLED",
            "Target": {
                "Arn": self.lambda_arn,
                "RoleArn": self.scheduler_role_arn,
                "Input": f'{{"action": "create_role", "request_id": "{request.request_id}"}}',
            },
            "FlexibleTimeWindow": {"Mode": "OFF"},
            "ActionAfterCompletion": "DELETE",
        }

        try:
            response = self.scheduler_client.create_schedule(**schedule_params)
            print(f"[Scheduler] Start schedule created successfully: {response.get('ScheduleArn', 'N/A')}")
        except self.scheduler_client.exceptions.ConflictException:
            # Schedule already exists, update it
            print(f"[Scheduler] Schedule already exists, updating: {schedule_name}")
            response = self.scheduler_client.update_schedule(**schedule_params)
            print(f"[Scheduler] Start schedule updated successfully: {response.get('ScheduleArn', 'N/A')}")
        except Exception as e:
            print(f"[Scheduler] ERROR creating start schedule: {e}")
            raise

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
        schedule_expression = f"at({request.end_time.strftime('%Y-%m-%dT%H:%M:%S')})"

        print(f"[Scheduler] Creating end schedule: {schedule_name}")
        print(f"[Scheduler] Schedule expression: {schedule_expression} (Asia/Seoul)")
        print(f"[Scheduler] Target Lambda ARN: {self.lambda_arn}")
        print(f"[Scheduler] Scheduler Role ARN: {self.scheduler_role_arn}")

        schedule_params = {
            "Name": schedule_name,
            "ScheduleExpression": schedule_expression,
            "ScheduleExpressionTimezone": "Asia/Seoul",
            "State": "ENABLED",
            "Target": {
                "Arn": self.lambda_arn,
                "RoleArn": self.scheduler_role_arn,
                "Input": f'{{"action": "delete_role", "request_id": "{request.request_id}"}}',
            },
            "FlexibleTimeWindow": {"Mode": "OFF"},
            "ActionAfterCompletion": "DELETE",
        }

        try:
            response = self.scheduler_client.create_schedule(**schedule_params)
            print(f"[Scheduler] End schedule created successfully: {response.get('ScheduleArn', 'N/A')}")
        except self.scheduler_client.exceptions.ConflictException:
            # Schedule already exists, update it
            print(f"[Scheduler] Schedule already exists, updating: {schedule_name}")
            response = self.scheduler_client.update_schedule(**schedule_params)
            print(f"[Scheduler] End schedule updated successfully: {response.get('ScheduleArn', 'N/A')}")
        except Exception as e:
            print(f"[Scheduler] ERROR creating end schedule: {e}")
            raise

        return schedule_name
    
    def delete_schedule(self, schedule_name: str) -> None:
        """
        Delete a schedule

        Args:
            schedule_name: Name of the schedule to delete
        """
        print(f"[Scheduler] Deleting schedule: {schedule_name}")
        try:
            self.scheduler_client.delete_schedule(Name=schedule_name)
            print(f"[Scheduler] Schedule deleted successfully: {schedule_name}")
        except self.scheduler_client.exceptions.ResourceNotFoundException:
            print(f"[Scheduler] Schedule not found (already deleted): {schedule_name}")
        except Exception as e:
            print(f"[Scheduler] ERROR deleting schedule {schedule_name}: {e}")
            # Don't raise - schedule deletion failure shouldn't block other operations
