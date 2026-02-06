"""
DynamoDB Repository for AWS Role Request System
"""
import boto3
from typing import Optional
from datetime import datetime, timezone, timedelta

from models import RoleRequest, RequestStatus

# Korea Standard Time (UTC+9)
KST = timezone(timedelta(hours=9))


class RoleRequestRepository:
    """Repository for role requests in DynamoDB"""
    
    def __init__(self, dynamodb_client=None, table_name: str = "RoleRequests"):
        self.dynamodb = dynamodb_client or boto3.resource("dynamodb")
        self.table = self.dynamodb.Table(table_name)
    
    def save(self, request: RoleRequest) -> None:
        """
        Save a role request
        
        Args:
            request: Role request to save
        """
        self.table.put_item(Item=request.to_dict())
    
    def get_by_id(self, request_id: str) -> Optional[RoleRequest]:
        """
        Get a role request by ID
        
        Args:
            request_id: Request ID
        
        Returns:
            RoleRequest or None if not found
        """
        response = self.table.get_item(Key={"request_id": request_id})
        item = response.get("Item")
        
        if not item:
            return None
        
        return RoleRequest.from_dict(item)
    
    def update_status(
        self,
        request_id: str,
        status: RequestStatus,
        approver_id: Optional[str] = None,
        rejection_reason: Optional[str] = None,
        role_arn: Optional[str] = None,
        policy_arn: Optional[str] = None,
    ) -> None:
        """
        Update request status
        
        Args:
            request_id: Request ID
            status: New status
            approver_id: Approver user ID (optional)
            rejection_reason: Rejection reason (optional)
            role_arn: Role ARN (optional)
            policy_arn: Policy ARN (optional)
        """
        update_expression = "SET #status = :status, updated_at = :updated_at"
        expression_values = {
            ":status": status.value,
            ":updated_at": datetime.now(KST).isoformat(),
        }
        expression_names = {"#status": "status"}
        
        if approver_id:
            update_expression += ", approver_id = :approver_id"
            expression_values[":approver_id"] = approver_id
        
        if rejection_reason:
            update_expression += ", rejection_reason = :rejection_reason"
            expression_values[":rejection_reason"] = rejection_reason
        
        if role_arn:
            update_expression += ", role_arn = :role_arn"
            expression_values[":role_arn"] = role_arn
        
        if policy_arn:
            update_expression += ", policy_arn = :policy_arn"
            expression_values[":policy_arn"] = policy_arn
        
        self.table.update_item(
            Key={"request_id": request_id},
            UpdateExpression=update_expression,
            ExpressionAttributeValues=expression_values,
            ExpressionAttributeNames=expression_names,
        )
    
    def update_post_id(self, request_id: str, post_id: str) -> None:
        """
        Update Mattermost post ID
        
        Args:
            request_id: Request ID
            post_id: Mattermost post ID
        """
        self.table.update_item(
            Key={"request_id": request_id},
            UpdateExpression="SET post_id = :post_id",
            ExpressionAttributeValues={":post_id": post_id},
        )
