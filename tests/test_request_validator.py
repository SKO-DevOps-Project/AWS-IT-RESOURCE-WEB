"""
Property-based tests for Request Validator

Feature: aws-role-request-system
"""
import pytest
from datetime import datetime, timedelta
from hypothesis import given, strategies as st, settings

from src.services.request_validator import RequestValidator
from src.models import VALID_ENVS, VALID_SERVICES


# Strategies for generating test data
valid_env_strategy = st.sampled_from(VALID_ENVS)
valid_service_strategy = st.sampled_from(VALID_SERVICES)
non_empty_string = st.text(min_size=1, max_size=50).filter(lambda x: x.strip())


class TestRequiredFieldValidation:
    """
    Property 1: Required Field Validation
    
    For any RoleRequest object, if any required field (iam_user_name, env, 
    service, start_time, end_time, purpose) is missing or empty, the 
    Request_Validator SHALL return a ValidationResult with is_valid=false 
    and an error specifying the missing field.
    
    **Validates: Requirements 1.2, 1.8**
    """
    
    @given(
        env=valid_env_strategy,
        service=valid_service_strategy,
        purpose=non_empty_string,
    )
    @settings(max_examples=100)
    def test_missing_iam_user_name_returns_error(self, env, service, purpose):
        """
        Feature: aws-role-request-system, Property 1: Required Field Validation
        Missing iam_user_name should return validation error
        """
        validator = RequestValidator()
        now = datetime.utcnow()
        start_time = now + timedelta(hours=1)
        end_time = now + timedelta(hours=2)
        
        result = validator.validate(
            iam_user_name=None,
            env=env,
            service=service,
            start_time=start_time,
            end_time=end_time,
            purpose=purpose,
            current_time=now,
        )
        
        assert not result.is_valid
        assert any(e.field == "iam_user_name" for e in result.errors)
    
    @given(
        iam_user_name=non_empty_string,
        service=valid_service_strategy,
        purpose=non_empty_string,
    )
    @settings(max_examples=100)
    def test_missing_env_returns_error(self, iam_user_name, service, purpose):
        """
        Feature: aws-role-request-system, Property 1: Required Field Validation
        Missing env should return validation error
        """
        validator = RequestValidator()
        now = datetime.utcnow()
        start_time = now + timedelta(hours=1)
        end_time = now + timedelta(hours=2)
        
        result = validator.validate(
            iam_user_name=iam_user_name,
            env=None,
            service=service,
            start_time=start_time,
            end_time=end_time,
            purpose=purpose,
            current_time=now,
        )
        
        assert not result.is_valid
        assert any(e.field == "env" for e in result.errors)
    
    @given(
        iam_user_name=non_empty_string,
        env=valid_env_strategy,
        purpose=non_empty_string,
    )
    @settings(max_examples=100)
    def test_missing_service_returns_error(self, iam_user_name, env, purpose):
        """
        Feature: aws-role-request-system, Property 1: Required Field Validation
        Missing service should return validation error
        """
        validator = RequestValidator()
        now = datetime.utcnow()
        start_time = now + timedelta(hours=1)
        end_time = now + timedelta(hours=2)
        
        result = validator.validate(
            iam_user_name=iam_user_name,
            env=env,
            service=None,
            start_time=start_time,
            end_time=end_time,
            purpose=purpose,
            current_time=now,
        )
        
        assert not result.is_valid
        assert any(e.field == "service" for e in result.errors)
    
    @given(
        iam_user_name=non_empty_string,
        env=valid_env_strategy,
        service=valid_service_strategy,
    )
    @settings(max_examples=100)
    def test_missing_purpose_returns_error(self, iam_user_name, env, service):
        """
        Feature: aws-role-request-system, Property 1: Required Field Validation
        Missing purpose should return validation error
        """
        validator = RequestValidator()
        now = datetime.utcnow()
        start_time = now + timedelta(hours=1)
        end_time = now + timedelta(hours=2)
        
        result = validator.validate(
            iam_user_name=iam_user_name,
            env=env,
            service=service,
            start_time=start_time,
            end_time=end_time,
            purpose=None,
            current_time=now,
        )
        
        assert not result.is_valid
        assert any(e.field == "purpose" for e in result.errors)
    
    @given(
        iam_user_name=non_empty_string,
        env=valid_env_strategy,
        service=valid_service_strategy,
        purpose=non_empty_string,
    )
    @settings(max_examples=100)
    def test_missing_start_time_returns_error(self, iam_user_name, env, service, purpose):
        """
        Feature: aws-role-request-system, Property 1: Required Field Validation
        Missing start_time should return validation error
        """
        validator = RequestValidator()
        now = datetime.utcnow()
        end_time = now + timedelta(hours=2)
        
        result = validator.validate(
            iam_user_name=iam_user_name,
            env=env,
            service=service,
            start_time=None,
            end_time=end_time,
            purpose=purpose,
            current_time=now,
        )
        
        assert not result.is_valid
        assert any(e.field == "start_time" for e in result.errors)
    
    @given(
        iam_user_name=non_empty_string,
        env=valid_env_strategy,
        service=valid_service_strategy,
        purpose=non_empty_string,
    )
    @settings(max_examples=100)
    def test_missing_end_time_returns_error(self, iam_user_name, env, service, purpose):
        """
        Feature: aws-role-request-system, Property 1: Required Field Validation
        Missing end_time should return validation error
        """
        validator = RequestValidator()
        now = datetime.utcnow()
        start_time = now + timedelta(hours=1)
        
        result = validator.validate(
            iam_user_name=iam_user_name,
            env=env,
            service=service,
            start_time=start_time,
            end_time=None,
            purpose=purpose,
            current_time=now,
        )
        
        assert not result.is_valid
        assert any(e.field == "end_time" for e in result.errors)
    
    @given(
        env=valid_env_strategy,
        service=valid_service_strategy,
        purpose=non_empty_string,
    )
    @settings(max_examples=100)
    def test_empty_iam_user_name_returns_error(self, env, service, purpose):
        """
        Feature: aws-role-request-system, Property 1: Required Field Validation
        Empty iam_user_name should return validation error
        """
        validator = RequestValidator()
        now = datetime.utcnow()
        start_time = now + timedelta(hours=1)
        end_time = now + timedelta(hours=2)
        
        result = validator.validate(
            iam_user_name="   ",  # whitespace only
            env=env,
            service=service,
            start_time=start_time,
            end_time=end_time,
            purpose=purpose,
            current_time=now,
        )
        
        assert not result.is_valid
        assert any(e.field == "iam_user_name" for e in result.errors)
    
    @given(
        iam_user_name=non_empty_string,
        env=valid_env_strategy,
        service=valid_service_strategy,
        purpose=non_empty_string,
    )
    @settings(max_examples=100)
    def test_all_valid_fields_returns_valid(self, iam_user_name, env, service, purpose):
        """
        Feature: aws-role-request-system, Property 1: Required Field Validation
        All valid fields should return is_valid=True
        """
        validator = RequestValidator()
        now = datetime.utcnow()
        start_time = now + timedelta(hours=1)
        end_time = now + timedelta(hours=2)
        
        result = validator.validate(
            iam_user_name=iam_user_name,
            env=env,
            service=service,
            start_time=start_time,
            end_time=end_time,
            purpose=purpose,
            current_time=now,
        )
        
        assert result.is_valid
        assert len(result.errors) == 0


class TestEnumValueValidation:
    """
    Property 2: Enum Value Validation
    
    For any string value for Env or Service field, the Request_Validator SHALL 
    accept only the predefined valid values (5 Env options, 18 Service options) 
    and reject all other values with appropriate error messages.
    
    **Validates: Requirements 1.4, 1.5**
    """
    
    @given(
        iam_user_name=non_empty_string,
        service=valid_service_strategy,
        purpose=non_empty_string,
        invalid_env=st.text(min_size=1, max_size=20).filter(
            lambda x: x.strip() and x not in VALID_ENVS
        ),
    )
    @settings(max_examples=100)
    def test_invalid_env_returns_error(self, iam_user_name, service, purpose, invalid_env):
        """
        Feature: aws-role-request-system, Property 2: Enum Value Validation
        Invalid env value should return validation error
        """
        validator = RequestValidator()
        now = datetime.utcnow()
        start_time = now + timedelta(hours=1)
        end_time = now + timedelta(hours=2)
        
        result = validator.validate(
            iam_user_name=iam_user_name,
            env=invalid_env,
            service=service,
            start_time=start_time,
            end_time=end_time,
            purpose=purpose,
            current_time=now,
        )
        
        assert not result.is_valid
        assert any(e.field == "env" for e in result.errors)
    
    @given(
        iam_user_name=non_empty_string,
        env=valid_env_strategy,
        purpose=non_empty_string,
        invalid_service=st.text(min_size=1, max_size=30).filter(
            lambda x: x.strip() and x not in VALID_SERVICES
        ),
    )
    @settings(max_examples=100)
    def test_invalid_service_returns_error(self, iam_user_name, env, purpose, invalid_service):
        """
        Feature: aws-role-request-system, Property 2: Enum Value Validation
        Invalid service value should return validation error
        """
        validator = RequestValidator()
        now = datetime.utcnow()
        start_time = now + timedelta(hours=1)
        end_time = now + timedelta(hours=2)
        
        result = validator.validate(
            iam_user_name=iam_user_name,
            env=env,
            service=invalid_service,
            start_time=start_time,
            end_time=end_time,
            purpose=purpose,
            current_time=now,
        )
        
        assert not result.is_valid
        assert any(e.field == "service" for e in result.errors)
    
    @given(env=valid_env_strategy)
    @settings(max_examples=100)
    def test_all_valid_envs_accepted(self, env):
        """
        Feature: aws-role-request-system, Property 2: Enum Value Validation
        All valid env values should be accepted
        """
        validator = RequestValidator()
        now = datetime.utcnow()
        start_time = now + timedelta(hours=1)
        end_time = now + timedelta(hours=2)
        
        result = validator.validate(
            iam_user_name="test_user",
            env=env,
            service="safety",
            start_time=start_time,
            end_time=end_time,
            purpose="test purpose",
            current_time=now,
        )
        
        # Should not have env error
        assert not any(e.field == "env" for e in result.errors)
    
    @given(service=valid_service_strategy)
    @settings(max_examples=100)
    def test_all_valid_services_accepted(self, service):
        """
        Feature: aws-role-request-system, Property 2: Enum Value Validation
        All valid service values should be accepted
        """
        validator = RequestValidator()
        now = datetime.utcnow()
        start_time = now + timedelta(hours=1)
        end_time = now + timedelta(hours=2)
        
        result = validator.validate(
            iam_user_name="test_user",
            env="prod",
            service=service,
            start_time=start_time,
            end_time=end_time,
            purpose="test purpose",
            current_time=now,
        )
        
        # Should not have service error
        assert not any(e.field == "service" for e in result.errors)



class TestTimeConstraintValidation:
    """
    Property 3: Time Constraint Validation
    
    For any time range (start_time, end_time), the Request_Validator SHALL 
    reject requests where:
    - start_time is in the past
    - duration (end_time - start_time) exceeds 24 hours
    - time format is invalid
    
    **Validates: Requirements 1.6, 1.7**
    """
    
    @given(
        hours_in_past=st.integers(min_value=1, max_value=100),
    )
    @settings(max_examples=100)
    def test_past_start_time_returns_error(self, hours_in_past):
        """
        Feature: aws-role-request-system, Property 3: Time Constraint Validation
        Start time in the past should return validation error
        """
        validator = RequestValidator()
        now = datetime.utcnow()
        start_time = now - timedelta(hours=hours_in_past)
        end_time = start_time + timedelta(hours=2)
        
        result = validator.validate(
            iam_user_name="test_user",
            env="prod",
            service="safety",
            start_time=start_time,
            end_time=end_time,
            purpose="test purpose",
            current_time=now,
        )
        
        assert not result.is_valid
        assert any(e.field == "start_time" for e in result.errors)
    
    @given(
        hours_over_24=st.integers(min_value=1, max_value=100),
    )
    @settings(max_examples=100)
    def test_duration_exceeds_24_hours_returns_error(self, hours_over_24):
        """
        Feature: aws-role-request-system, Property 3: Time Constraint Validation
        Duration exceeding 24 hours should return validation error
        """
        validator = RequestValidator()
        now = datetime.utcnow()
        start_time = now + timedelta(hours=1)
        end_time = start_time + timedelta(hours=24 + hours_over_24)
        
        result = validator.validate(
            iam_user_name="test_user",
            env="prod",
            service="safety",
            start_time=start_time,
            end_time=end_time,
            purpose="test purpose",
            current_time=now,
        )
        
        assert not result.is_valid
        assert any(e.field == "end_time" for e in result.errors)
    
    @given(
        duration_hours=st.integers(min_value=1, max_value=24),
    )
    @settings(max_examples=100)
    def test_valid_duration_within_24_hours_accepted(self, duration_hours):
        """
        Feature: aws-role-request-system, Property 3: Time Constraint Validation
        Duration within 24 hours should be accepted
        """
        validator = RequestValidator()
        now = datetime.utcnow()
        start_time = now + timedelta(hours=1)
        end_time = start_time + timedelta(hours=duration_hours)
        
        result = validator.validate(
            iam_user_name="test_user",
            env="prod",
            service="safety",
            start_time=start_time,
            end_time=end_time,
            purpose="test purpose",
            current_time=now,
        )
        
        # Should not have time-related errors
        assert not any(e.field in ["start_time", "end_time"] for e in result.errors)
    
    @given(
        hours_in_past=st.integers(min_value=1, max_value=100),
    )
    @settings(max_examples=100)
    def test_master_request_allows_past_start_time(self, hours_in_past):
        """
        Feature: aws-role-request-system, Property 3: Time Constraint Validation
        Master request should allow past start time
        """
        validator = RequestValidator()
        now = datetime.utcnow()
        start_time = now - timedelta(hours=hours_in_past)
        end_time = now + timedelta(hours=2)  # End time in future
        
        result = validator.validate(
            iam_user_name="test_user",
            env="prod",
            service="safety",
            start_time=start_time,
            end_time=end_time,
            purpose="test purpose",
            is_master_request=True,
            current_time=now,
        )
        
        # Should not have start_time error for master request
        assert not any(e.field == "start_time" for e in result.errors)
    
    def test_end_time_before_start_time_returns_error(self):
        """
        Feature: aws-role-request-system, Property 3: Time Constraint Validation
        End time before start time should return validation error
        """
        validator = RequestValidator()
        now = datetime.utcnow()
        start_time = now + timedelta(hours=5)
        end_time = now + timedelta(hours=2)  # Before start_time
        
        result = validator.validate(
            iam_user_name="test_user",
            env="prod",
            service="safety",
            start_time=start_time,
            end_time=end_time,
            purpose="test purpose",
            current_time=now,
        )
        
        assert not result.is_valid
        assert any(e.field == "end_time" for e in result.errors)
