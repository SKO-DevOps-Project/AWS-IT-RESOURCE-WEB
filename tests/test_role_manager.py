"""
Property-based tests for Role Manager

Feature: aws-role-request-system
"""
import pytest
import json
from unittest.mock import MagicMock
from hypothesis import given, strategies as st, settings
from datetime import datetime, timedelta

from src.services.role_manager import RoleManager
from src.models import RoleRequest, RequestStatus, VALID_ENVS, VALID_SERVICES


# Strategies
non_empty_string = st.text(min_size=1, max_size=50).filter(lambda x: x.strip())
valid_env_strategy = st.sampled_from(VALID_ENVS)
valid_service_strategy = st.sampled_from(VALID_SERVICES)


class TestDynamicRoleUniqueness:
    """
    Property 4: Dynamic Role Uniqueness
    
    For any set of approved requests (including concurrent requests for the 
    same Env/Service), the Role_Manager SHALL generate unique Role names and 
    unique EventBridge schedule names, ensuring no naming conflicts occur.
    
    **Validates: Requirements 3.2, 5.2**
    """
    
    @given(
        iam_user_name=non_empty_string,
        env=valid_env_strategy,
        service=valid_service_strategy,
        num_requests=st.integers(min_value=2, max_value=5),
    )
    @settings(max_examples=50)
    def test_concurrent_requests_generate_unique_role_names(
        self,
        iam_user_name,
        env,
        service,
        num_requests,
    ):
        """
        Feature: aws-role-request-system, Property 4: Dynamic Role Uniqueness
        Multiple concurrent requests should generate unique role names
        """
        role_manager = RoleManager(account_id="123456789012")
        
        # Create multiple requests with same env/service
        requests = []
        for i in range(num_requests):
            request = RoleRequest(
                request_id=f"req-{i}",
                requester_mattermost_id="user1",
                requester_name="Test User",
                iam_user_name=iam_user_name,
                env=env,
                service=service,
                start_time=datetime.utcnow() + timedelta(hours=1),
                end_time=datetime.utcnow() + timedelta(hours=2),
                purpose="test",
            )
            requests.append(request)
        
        # Generate role names
        role_names = [role_manager.generate_role_name(req) for req in requests]
        
        # Verify all role names are unique
        assert len(role_names) == len(set(role_names))


class TestPolicyGenerationCorrectness:
    """
    Property 5: Policy Generation Correctness
    
    For any approved RoleRequest with Env=E and Service=S, the generated IAM 
    Policy SHALL:
    - Allow actions only on resources tagged with both Env=E AND Service=S
    - Trust Policy SHALL allow only the specified IAM user
    - Trust Policy SHALL include IP restriction condition
    
    **Validates: Requirements 3.3, 3.4, 3.5**
    """
    
    @given(
        iam_user_name=non_empty_string,
        env=valid_env_strategy,
        service=valid_service_strategy,
    )
    @settings(max_examples=100)
    def test_permission_policy_has_correct_tag_conditions(
        self,
        iam_user_name,
        env,
        service,
    ):
        """
        Feature: aws-role-request-system, Property 5: Policy Generation Correctness
        Permission policy should have correct Env and Service tag conditions
        """
        role_manager = RoleManager(account_id="123456789012")
        
        request = RoleRequest(
            request_id="test-req",
            requester_mattermost_id="user1",
            requester_name="Test User",
            iam_user_name=iam_user_name,
            env=env,
            service=service,
            start_time=datetime.utcnow() + timedelta(hours=1),
            end_time=datetime.utcnow() + timedelta(hours=2),
            purpose="test",
        )
        
        policy = role_manager._generate_permission_policy(request)
        
        # Verify policy structure
        assert "Statement" in policy
        statement = policy["Statement"][0]
        
        # Verify tag conditions
        assert "Condition" in statement
        assert "StringEquals" in statement["Condition"]
        tag_conditions = statement["Condition"]["StringEquals"]
        
        assert "aws:ResourceTag/Env" in tag_conditions
        assert tag_conditions["aws:ResourceTag/Env"] == env
        
        assert "aws:ResourceTag/Service" in tag_conditions
        assert tag_conditions["aws:ResourceTag/Service"] == service
    
    @given(
        iam_user_name=non_empty_string,
        env=valid_env_strategy,
        service=valid_service_strategy,
    )
    @settings(max_examples=100)
    def test_trust_policy_allows_only_specified_user(
        self,
        iam_user_name,
        env,
        service,
    ):
        """
        Feature: aws-role-request-system, Property 5: Policy Generation Correctness
        Trust policy should allow only the specified IAM user
        """
        account_id = "123456789012"
        role_manager = RoleManager(account_id=account_id)
        
        request = RoleRequest(
            request_id="test-req",
            requester_mattermost_id="user1",
            requester_name="Test User",
            iam_user_name=iam_user_name,
            env=env,
            service=service,
            start_time=datetime.utcnow() + timedelta(hours=1),
            end_time=datetime.utcnow() + timedelta(hours=2),
            purpose="test",
        )
        
        trust_policy = role_manager._generate_trust_policy(request)
        
        # Verify trust policy structure
        assert "Statement" in trust_policy
        statement = trust_policy["Statement"][0]
        
        # Verify principal
        assert "Principal" in statement
        assert "AWS" in statement["Principal"]
        expected_arn = f"arn:aws:iam::{account_id}:user/{iam_user_name}"
        assert statement["Principal"]["AWS"] == expected_arn
    
    @given(
        iam_user_name=non_empty_string,
        env=valid_env_strategy,
        service=valid_service_strategy,
    )
    @settings(max_examples=100)
    def test_trust_policy_has_ip_restriction(
        self,
        iam_user_name,
        env,
        service,
    ):
        """
        Feature: aws-role-request-system, Property 5: Policy Generation Correctness
        Trust policy should include IP restriction condition
        """
        role_manager = RoleManager(
            account_id="123456789012",
            company_ip_range="10.0.0.0/8",
        )
        
        request = RoleRequest(
            request_id="test-req",
            requester_mattermost_id="user1",
            requester_name="Test User",
            iam_user_name=iam_user_name,
            env=env,
            service=service,
            start_time=datetime.utcnow() + timedelta(hours=1),
            end_time=datetime.utcnow() + timedelta(hours=2),
            purpose="test",
        )
        
        trust_policy = role_manager._generate_trust_policy(request)
        
        # Verify IP condition
        statement = trust_policy["Statement"][0]
        assert "Condition" in statement
        assert "IpAddress" in statement["Condition"]
        assert "aws:SourceIp" in statement["Condition"]["IpAddress"]


class TestCloudTrailSessionNaming:
    """
    Property 9: CloudTrail Session Naming
    
    For any created Dynamic_Role, the session name configuration SHALL include 
    the requester identifier to enable CloudTrail tracking of API calls made 
    using the assumed role.
    
    **Validates: Requirements 7.1**
    """
    
    @given(
        iam_user_name=non_empty_string,
        env=valid_env_strategy,
        service=valid_service_strategy,
    )
    @settings(max_examples=100)
    def test_role_name_includes_requester_identifier(
        self,
        iam_user_name,
        env,
        service,
    ):
        """
        Feature: aws-role-request-system, Property 9: CloudTrail Session Naming
        Role name should include requester identifier for CloudTrail tracking
        """
        role_manager = RoleManager(account_id="123456789012")
        
        request = RoleRequest(
            request_id="test-req",
            requester_mattermost_id="user1",
            requester_name="Test User",
            iam_user_name=iam_user_name,
            env=env,
            service=service,
            start_time=datetime.utcnow() + timedelta(hours=1),
            end_time=datetime.utcnow() + timedelta(hours=2),
            purpose="test",
        )
        
        role_name = role_manager.generate_role_name(request)
        
        # Verify role name contains requester identifier (iam_user_name)
        assert iam_user_name in role_name
        
        # Verify role name contains env and service for tracking
        assert env in role_name
        assert service in role_name
