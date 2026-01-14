"""
Property-based tests for Mattermost Client

Feature: aws-role-request-system
"""
import pytest
from hypothesis import given, strategies as st, settings

from src.services.mattermost_client import (
    create_approval_message,
    Attachment,
)
from src.models import VALID_ENVS, VALID_SERVICES


# Strategies
non_empty_string = st.text(min_size=1, max_size=50).filter(lambda x: x.strip())
valid_env_strategy = st.sampled_from(VALID_ENVS)
valid_service_strategy = st.sampled_from(VALID_SERVICES)


class TestApprovalMessageContent:
    """
    Property 8: Approval Message Content
    
    For any validated request forwarded to Approval_Channel, the interactive 
    message SHALL contain all request details (requester_name, iam_user_name, 
    env, service, time_range, purpose) and functional approve/reject buttons.
    
    **Validates: Requirements 2.1**
    """
    
    @given(
        request_id=st.uuids().map(str),
        requester_name=non_empty_string,
        iam_user_name=non_empty_string,
        env=valid_env_strategy,
        service=valid_service_strategy,
        start_time=non_empty_string,
        end_time=non_empty_string,
        purpose=non_empty_string,
    )
    @settings(max_examples=100)
    def test_approval_message_contains_all_fields(
        self,
        request_id,
        requester_name,
        iam_user_name,
        env,
        service,
        start_time,
        end_time,
        purpose,
    ):
        """
        Feature: aws-role-request-system, Property 8: Approval Message Content
        Approval message should contain all request details
        """
        attachment = create_approval_message(
            request_id=request_id,
            requester_name=requester_name,
            iam_user_name=iam_user_name,
            env=env,
            service=service,
            start_time=start_time,
            end_time=end_time,
            purpose=purpose,
            callback_url="https://example.com/callback",
        )
        
        attachment_dict = attachment.to_dict()
        fields = attachment_dict["fields"]
        
        # Extract field values
        field_values = {f["title"]: f["value"] for f in fields}
        
        # Verify all required fields are present
        assert "요청자" in field_values
        assert field_values["요청자"] == requester_name
        
        assert "IAM User" in field_values
        assert field_values["IAM User"] == iam_user_name
        
        assert "Environment" in field_values
        assert field_values["Environment"] == env
        
        assert "Service" in field_values
        assert field_values["Service"] == service
        
        assert "시작 시간" in field_values
        assert field_values["시작 시간"] == start_time
        
        assert "종료 시간" in field_values
        assert field_values["종료 시간"] == end_time
        
        assert "목적" in field_values
        assert field_values["목적"] == purpose
    
    @given(
        request_id=st.uuids().map(str),
        requester_name=non_empty_string,
        iam_user_name=non_empty_string,
        env=valid_env_strategy,
        service=valid_service_strategy,
    )
    @settings(max_examples=100)
    def test_approval_message_has_approve_reject_buttons(
        self,
        request_id,
        requester_name,
        iam_user_name,
        env,
        service,
    ):
        """
        Feature: aws-role-request-system, Property 8: Approval Message Content
        Approval message should have approve and reject buttons
        """
        attachment = create_approval_message(
            request_id=request_id,
            requester_name=requester_name,
            iam_user_name=iam_user_name,
            env=env,
            service=service,
            start_time="09:00",
            end_time="18:00",
            purpose="test purpose",
            callback_url="https://example.com/callback",
        )
        
        attachment_dict = attachment.to_dict()
        actions = attachment_dict["actions"]
        
        # Verify approve and reject buttons exist
        action_ids = [a["id"] for a in actions]
        assert "approve" in action_ids
        assert "reject" in action_ids
        
        # Verify button styles
        approve_action = next(a for a in actions if a["id"] == "approve")
        reject_action = next(a for a in actions if a["id"] == "reject")
        
        assert approve_action["style"] == "good"
        assert reject_action["style"] == "danger"
        
        # Verify request_id is in context
        assert approve_action["integration"]["context"]["request_id"] == request_id
        assert reject_action["integration"]["context"]["request_id"] == request_id
    
    @given(
        request_id=st.uuids().map(str),
    )
    @settings(max_examples=100)
    def test_approval_message_buttons_have_correct_actions(self, request_id):
        """
        Feature: aws-role-request-system, Property 8: Approval Message Content
        Button actions should have correct action types
        """
        attachment = create_approval_message(
            request_id=request_id,
            requester_name="Test User",
            iam_user_name="test_user",
            env="prod",
            service="safety",
            start_time="09:00",
            end_time="18:00",
            purpose="test purpose",
            callback_url="https://example.com/callback",
        )
        
        attachment_dict = attachment.to_dict()
        actions = attachment_dict["actions"]
        
        approve_action = next(a for a in actions if a["id"] == "approve")
        reject_action = next(a for a in actions if a["id"] == "reject")
        
        assert approve_action["integration"]["context"]["action"] == "approve"
        assert reject_action["integration"]["context"]["action"] == "reject"
