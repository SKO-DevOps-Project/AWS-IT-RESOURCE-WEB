"""
Property-based tests for Request Handler

Feature: aws-role-request-system
"""
import pytest
import os
from unittest.mock import MagicMock, patch
from hypothesis import given, strategies as st, settings

from src.handlers.request_handler import RequestHandler
from src.models import VALID_ENVS, VALID_SERVICES


# Strategies
non_empty_string = st.text(min_size=1, max_size=50).filter(lambda x: x.strip())
valid_env_strategy = st.sampled_from(VALID_ENVS)
valid_service_strategy = st.sampled_from(VALID_SERVICES)


class TestAdminAuthorization:
    """
    Property 10: Admin Authorization
    
    For any /master-request-role command, the System SHALL verify the user 
    is in the authorized Admin list and reject with "권한이 없습니다" error 
    if not authorized.
    
    **Validates: Requirements 8.3, 8.4**
    """
    
    @given(
        non_admin_user_id=st.text(min_size=5, max_size=20).filter(
            lambda x: x.strip() and x not in ["admin1", "admin2"]
        ),
    )
    @settings(max_examples=100)
    def test_non_admin_user_rejected(self, non_admin_user_id):
        """
        Feature: aws-role-request-system, Property 10: Admin Authorization
        Non-admin users should be rejected with "권한이 없습니다"
        """
        with patch.dict(os.environ, {"ADMIN_USER_IDS": "admin1,admin2"}):
            # Reload the module to pick up new env var
            from src.handlers import request_handler
            request_handler.ADMIN_USER_IDS = ["admin1", "admin2"]
            
            handler = RequestHandler()
            
            event = {
                "user_id": non_admin_user_id,
                "user_name": "test_user",
                "text": "- IAM user명 : test\n- Env : prod\n- Service : safety\n- 시간 : 09-18시\n- 목적 : test",
            }
            
            result = handler.handle_master_request(event)
            
            assert "권한이 없습니다" in result["text"]
    
    @given(
        admin_index=st.integers(min_value=0, max_value=1),
    )
    @settings(max_examples=10)
    def test_admin_user_not_rejected_for_permission(self, admin_index):
        """
        Feature: aws-role-request-system, Property 10: Admin Authorization
        Admin users should not be rejected for permission
        """
        admin_ids = ["admin1", "admin2"]
        admin_user_id = admin_ids[admin_index]
        
        with patch.dict(os.environ, {"ADMIN_USER_IDS": "admin1,admin2"}):
            from src.handlers import request_handler
            request_handler.ADMIN_USER_IDS = admin_ids
            
            # Mock validator to avoid IAM check
            mock_validator = MagicMock()
            mock_validator.validate.return_value = MagicMock(is_valid=True, errors=[])
            mock_validator.validate_iam_user_exists.return_value = MagicMock(is_valid=True, errors=[])
            
            handler = RequestHandler(validator=mock_validator)
            
            event = {
                "user_id": admin_user_id,
                "user_name": "admin_user",
                "text": "- IAM user명 : test\n- Env : prod\n- Service : safety\n- 시간 : 09-18시\n- 목적 : test",
            }
            
            result = handler.handle_master_request(event)
            
            # Should not contain permission error
            assert "권한이 없습니다" not in result["text"]
    
    def test_is_admin_returns_true_for_admin(self):
        """
        Feature: aws-role-request-system, Property 10: Admin Authorization
        is_admin should return True for admin users
        """
        with patch.dict(os.environ, {"ADMIN_USER_IDS": "admin1,admin2"}):
            from src.handlers import request_handler
            request_handler.ADMIN_USER_IDS = ["admin1", "admin2"]
            
            handler = RequestHandler()
            
            assert handler.is_admin("admin1") is True
            assert handler.is_admin("admin2") is True
    
    def test_is_admin_returns_false_for_non_admin(self):
        """
        Feature: aws-role-request-system, Property 10: Admin Authorization
        is_admin should return False for non-admin users
        """
        with patch.dict(os.environ, {"ADMIN_USER_IDS": "admin1,admin2"}):
            from src.handlers import request_handler
            request_handler.ADMIN_USER_IDS = ["admin1", "admin2"]
            
            handler = RequestHandler()
            
            assert handler.is_admin("regular_user") is False
            assert handler.is_admin("") is False


class TestMasterRequestImmediateProcessing:
    """
    Property 11: Master Request Immediate Processing
    
    For any valid /master-request-role request from an authorized Admin, 
    the System SHALL immediately trigger role creation without forwarding 
    to Approval_Channel, and the request SHALL be stored with status 
    "approved" and the Admin as approver.
    
    **Validates: Requirements 8.6, 8.8**
    """
    
    @given(
        env=valid_env_strategy,
        service=valid_service_strategy,
        purpose=non_empty_string,
    )
    @settings(max_examples=50)
    def test_master_request_creates_approved_status(self, env, service, purpose):
        """
        Feature: aws-role-request-system, Property 11: Master Request Immediate Processing
        Master request should create request with approved status
        """
        admin_user_id = "admin1"
        
        with patch.dict(os.environ, {"ADMIN_USER_IDS": "admin1,admin2"}):
            from src.handlers import request_handler
            request_handler.ADMIN_USER_IDS = ["admin1", "admin2"]
            
            # Mock validator
            mock_validator = MagicMock()
            mock_validator.validate.return_value = MagicMock(is_valid=True, errors=[])
            mock_validator.validate_iam_user_exists.return_value = MagicMock(is_valid=True, errors=[])
            
            # Mock repository to capture saved request
            mock_repository = MagicMock()
            saved_requests = []
            mock_repository.save.side_effect = lambda r: saved_requests.append(r)
            
            handler = RequestHandler(
                validator=mock_validator,
                repository=mock_repository,
            )
            
            event = {
                "user_id": admin_user_id,
                "user_name": "admin_user",
                "text": f"- IAM user명 : test_user\n- Env : {env}\n- Service : {service}\n- 시간 : 09-18시\n- 목적 : {purpose}",
            }
            
            handler.handle_master_request(event)
            
            # Verify request was saved
            assert len(saved_requests) == 1
            saved_request = saved_requests[0]
            
            # Verify status is APPROVED
            from src.models import RequestStatus
            assert saved_request.status == RequestStatus.APPROVED
            
            # Verify admin is set as approver
            assert saved_request.approver_id == admin_user_id
            
            # Verify is_master_request flag
            assert saved_request.is_master_request is True
    
    def test_master_request_does_not_forward_to_approval_channel(self):
        """
        Feature: aws-role-request-system, Property 11: Master Request Immediate Processing
        Master request should not forward to approval channel
        """
        admin_user_id = "admin1"
        
        with patch.dict(os.environ, {"ADMIN_USER_IDS": "admin1,admin2"}):
            from src.handlers import request_handler
            request_handler.ADMIN_USER_IDS = ["admin1", "admin2"]
            
            # Mock validator
            mock_validator = MagicMock()
            mock_validator.validate.return_value = MagicMock(is_valid=True, errors=[])
            mock_validator.validate_iam_user_exists.return_value = MagicMock(is_valid=True, errors=[])
            
            # Mock mattermost client
            mock_mattermost = MagicMock()
            
            handler = RequestHandler(
                validator=mock_validator,
                mattermost_client=mock_mattermost,
            )
            
            event = {
                "user_id": admin_user_id,
                "user_name": "admin_user",
                "text": "- IAM user명 : test_user\n- Env : prod\n- Service : safety\n- 시간 : 09-18시\n- 목적 : test",
            }
            
            handler.handle_master_request(event)
            
            # Verify send_interactive_message was NOT called (no approval channel forward)
            mock_mattermost.send_interactive_message.assert_not_called()
    
    def test_master_request_triggers_role_creation(self):
        """
        Feature: aws-role-request-system, Property 11: Master Request Immediate Processing
        Master request should trigger immediate role creation
        """
        admin_user_id = "admin1"
        
        with patch.dict(os.environ, {"ADMIN_USER_IDS": "admin1,admin2"}):
            from src.handlers import request_handler
            request_handler.ADMIN_USER_IDS = ["admin1", "admin2"]
            
            # Mock validator
            mock_validator = MagicMock()
            mock_validator.validate.return_value = MagicMock(is_valid=True, errors=[])
            mock_validator.validate_iam_user_exists.return_value = MagicMock(is_valid=True, errors=[])
            
            # Mock role manager
            mock_role_manager = MagicMock()
            mock_role_manager.create_dynamic_role.return_value = {
                "role_arn": "arn:aws:iam::123456789:role/test-role",
                "policy_arn": "arn:aws:iam::123456789:policy/test-policy",
            }
            
            handler = RequestHandler(
                validator=mock_validator,
                role_manager=mock_role_manager,
            )
            
            event = {
                "user_id": admin_user_id,
                "user_name": "admin_user",
                "text": "- IAM user명 : test_user\n- Env : prod\n- Service : safety\n- 시간 : 09-18시\n- 목적 : test",
            }
            
            handler.handle_master_request(event)
            
            # Verify role creation was triggered
            mock_role_manager.create_dynamic_role.assert_called_once()
