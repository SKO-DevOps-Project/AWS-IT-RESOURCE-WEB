"""
Dashboard API Lambda Handler
Provides REST API for the dashboard frontend
"""
import os
import json
import time
import uuid
import hashlib
import secrets
import boto3
import jwt
import requests
from datetime import datetime, timedelta, timezone
from typing import Dict, Any, Optional, List
from boto3.dynamodb.conditions import Key, Attr

from models import (
    RoleRequest,
    RequestStatus,
)
from services.tag_config_service import get_valid_envs, get_valid_services, get_service_display_names
from services.mattermost_client import MattermostClient, create_work_request_notification
from services.notification_service import (
    notify_request_created,
    notify_approved,
    notify_rejected,
    notify_revoked,
    notify_role_created,
)
from services.request_validator import RequestValidator


# Korea Standard Time (UTC+9)
KST = timezone(timedelta(hours=9))

# DynamoDB tables
dynamodb = boto3.resource('dynamodb')
role_requests_table = dynamodb.Table(os.environ.get('ROLE_REQUESTS_TABLE', 'RoleRequests'))
activity_logs_table = dynamodb.Table(os.environ.get('ACTIVITY_LOGS_TABLE', 'ActivityLogs'))
work_requests_table = dynamodb.Table(os.environ.get('WORK_REQUESTS_TABLE', 'WorkRequests'))
api_keys_table = dynamodb.Table(os.environ.get('API_KEYS_TABLE', 'ApiKeys'))
users_table = dynamodb.Table(os.environ.get('USERS_TABLE', 'Users'))
team_members_table = dynamodb.Table(os.environ.get('TEAM_MEMBERS_TABLE', 'TeamMembers'))

# Mattermost
REQUEST_CHANNEL_ID = os.environ.get('REQUEST_CHANNEL_ID', '')
APPROVAL_CHANNEL_ID = os.environ.get('APPROVAL_CHANNEL_ID', '')
API_URL = os.environ.get('API_URL', '')

# JWT Configuration
JWT_SECRET = os.environ.get('JWT_SECRET', 'your-super-secret-jwt-key-change-this')
JWT_ALGORITHM = 'HS256'
JWT_ACCESS_TOKEN_EXPIRE_MINUTES = 60 * 24  # 24 hours
JWT_REFRESH_TOKEN_EXPIRE_DAYS = 7

# Admin user IDs (from environment variable)
ADMIN_USER_IDS = os.environ.get('ADMIN_USER_IDS', '').split(',')

# External login API (SKONS)
SKONS_LOGIN_URL = os.environ.get('SKONS_LOGIN_URL', 'https://auth.skons.net/accounts/sko/sso/login/')

# Activity logs cache (Lambda instance-level)
_activities_cache = {
    'items': None,
    'timestamp': 0
}
ACTIVITIES_CACHE_TTL = 30  # seconds

# Dashboard summary cache (Lambda instance-level)
_dashboard_cache = {
    'data': None,
    'timestamp': 0
}
DASHBOARD_CACHE_TTL = 120  # 2 minutes


def hash_api_key(api_key: str) -> str:
    """Hash API key for secure storage"""
    return hashlib.sha256(api_key.encode()).hexdigest()


def generate_api_key() -> str:
    """Generate a secure random API key"""
    return f"sk_{secrets.token_urlsafe(32)}"


def verify_api_key(api_key: str) -> Optional[Dict[str, Any]]:
    """
    Verify API key and return key info if valid
    Returns None if invalid
    """
    if not api_key:
        return None

    # Remove 'Bearer ' prefix if present
    if api_key.startswith('Bearer '):
        api_key = api_key[7:]

    try:
        # Hash the provided key to compare
        hashed_key = hash_api_key(api_key)

        result = api_keys_table.get_item(Key={'api_key': hashed_key})
        key_item = result.get('Item')

        if not key_item:
            return None

        # Check if key is active
        if key_item.get('status') != 'active':
            return None

        # Check expiration if set
        expires_at = key_item.get('expires_at')
        if expires_at:
            now_kst = datetime.now(KST).isoformat()
            if now_kst > expires_at:
                return None

        return key_item
    except Exception as e:
        print(f"[verify_api_key] Error: {e}")
        return None


def require_api_key(event: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """
    Extract and verify API key from request headers
    Returns key info if valid, None otherwise
    """
    headers = event.get('headers', {}) or {}

    # Check Authorization header
    auth_header = headers.get('Authorization') or headers.get('authorization')
    if auth_header:
        return verify_api_key(auth_header)

    # Check X-API-Key header
    api_key_header = headers.get('X-API-Key') or headers.get('x-api-key')
    if api_key_header:
        return verify_api_key(api_key_header)

    return None


# ========== JWT Authentication Functions ==========

def create_access_token(user_id: str, is_admin: bool = False) -> str:
    """Create JWT access token"""
    now = datetime.now(timezone.utc)
    expire = now + timedelta(minutes=JWT_ACCESS_TOKEN_EXPIRE_MINUTES)

    payload = {
        'sub': user_id,
        'is_admin': is_admin,
        'type': 'access',
        'iat': now,
        'exp': expire
    }

    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)


def create_refresh_token(user_id: str) -> str:
    """Create JWT refresh token"""
    now = datetime.now(timezone.utc)
    expire = now + timedelta(days=JWT_REFRESH_TOKEN_EXPIRE_DAYS)

    payload = {
        'sub': user_id,
        'type': 'refresh',
        'iat': now,
        'exp': expire
    }

    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)


def verify_jwt_token(token: str, token_type: str = 'access') -> Optional[Dict[str, Any]]:
    """
    Verify JWT token and return payload if valid
    Returns None if invalid
    """
    try:
        # Remove 'Bearer ' prefix if present
        if token.startswith('Bearer '):
            token = token[7:]

        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])

        # Check token type
        if payload.get('type') != token_type:
            return None

        return payload
    except jwt.ExpiredSignatureError:
        print("[verify_jwt_token] Token expired")
        return None
    except jwt.InvalidTokenError as e:
        print(f"[verify_jwt_token] Invalid token: {e}")
        return None


def get_current_user(event: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """
    Extract and verify JWT from request headers
    Returns user info if valid, None otherwise
    """
    headers = event.get('headers', {}) or {}

    auth_header = headers.get('Authorization') or headers.get('authorization')
    if not auth_header:
        return None

    payload = verify_jwt_token(auth_header, 'access')
    if not payload:
        return None

    # Get user from database
    user_id = payload.get('sub')
    if not user_id:
        return None

    try:
        result = users_table.get_item(Key={'user_id': user_id})
        user = result.get('Item')
        if user and user.get('is_active', True):
            return user
    except Exception as e:
        print(f"[get_current_user] Error: {e}")

    return None


def authenticate_with_skons(user_id: str, password: str) -> bool:
    """
    Authenticate user with SKONS external API
    Calls the external SKONS login API to verify credentials
    """
    try:
        url = SKONS_LOGIN_URL

        payload = json.dumps({
            "username": user_id,
            "password": password,
        })
        headers = {
            'Content-Type': 'application/json'
        }

        response = requests.request("POST", url, headers=headers, data=payload, timeout=10)

        print(f"[authenticate_with_skons] Response status: {response.status_code}")
        print(f"[authenticate_with_skons] Response text: {response.text[:200] if response.text else 'empty'}")

        # Check if login successful - response should be {"result": "ok"}
        if response.status_code == 200:
            try:
                result = response.json().get("result")
                if result == "ok":
                    print(f"[authenticate_with_skons] Success for user: {user_id}")
                    return True
            except:
                pass
            print(f"[authenticate_with_skons] Failed for user: {user_id}")
            return False

        print(f"[authenticate_with_skons] Failed for user: {user_id}, status: {response.status_code}")
        return False

    except Exception as e:
        print(f"[authenticate_with_skons] Error: {e}")
        return False


def lambda_handler(event: Dict[str, Any], context: Any) -> Dict[str, Any]:
    """Main Lambda handler for dashboard API"""

    http_method = event.get('httpMethod', '')
    path = event.get('path', '')
    path_params = event.get('pathParameters') or {}
    query_params = event.get('queryStringParameters') or {}

    print(f"[dashboard_api] {http_method} {path}")
    print(f"[dashboard_api] path_params: {path_params}")
    print(f"[dashboard_api] query_params: {query_params}")

    try:
        # Handle OPTIONS preflight requests
        if http_method == 'OPTIONS':
            return response(200, {})

        # Route requests
        if path == '/api/dashboard-summary' and http_method == 'GET':
            return get_dashboard_summary(query_params)

        elif path == '/api/tickets' and http_method == 'GET':
            return get_tickets(query_params)

        elif path.startswith('/api/tickets/') and http_method == 'GET':
            request_id = path_params.get('request_id') or path.split('/')[-1]
            return get_ticket_detail(request_id)

        elif path.startswith('/api/tickets/') and http_method == 'PATCH':
            request_id = path_params.get('request_id') or path.split('/')[-1]
            body = json.loads(event.get('body', '{}'))
            return update_ticket(request_id, body, event)

        elif path == '/api/activities' and http_method == 'GET':
            return get_activities(query_params)

        elif path.startswith('/api/users/') and path.endswith('/activities') and http_method == 'GET':
            iam_user_name = path_params.get('iam_user_name') or path.split('/')[3]
            return get_user_activities(iam_user_name, query_params)

        elif path == '/api/services' and http_method == 'GET':
            return get_services()

        elif path == '/api/work-requests' and http_method == 'GET':
            return get_work_requests(query_params)

        elif path == '/api/work-requests' and http_method == 'POST':
            body = json.loads(event.get('body', '{}'))
            return create_work_request(body)

        elif path.startswith('/api/work-requests/') and '/tickets' in path and http_method == 'GET':
            # GET /api/work-requests/{request_id}/tickets
            request_id = path.split('/')[3]
            return get_work_request_tickets(request_id)

        elif path.startswith('/api/work-requests/') and http_method == 'GET':
            # GET /api/work-requests/{request_id}
            request_id = path_params.get('request_id') or path.split('/')[-1]
            return get_work_request_detail(request_id)

        elif path.startswith('/api/work-requests/') and http_method == 'PATCH':
            request_id = path_params.get('request_id') or path.split('/')[-1]
            body = json.loads(event.get('body', '{}'))
            return update_work_request(request_id, body, event)

        # API Key management endpoints (admin only)
        elif path == '/api/api-keys' and http_method == 'GET':
            return get_api_keys(event)

        elif path == '/api/api-keys' and http_method == 'POST':
            body = json.loads(event.get('body', '{}'))
            return create_api_key(event, body)

        elif path.startswith('/api/api-keys/') and http_method == 'DELETE':
            key_id = path_params.get('key_id') or path.split('/')[-1]
            return revoke_api_key(event, key_id)

        # Verify API Key endpoint (for external systems to test their key)
        elif path == '/api/verify-key' and http_method == 'GET':
            return verify_api_key_endpoint(event)

        # Authentication endpoints
        elif path == '/api/auth/login' and http_method == 'POST':
            body = json.loads(event.get('body', '{}'))
            return login(body)

        elif path == '/api/auth/me' and http_method == 'GET':
            return get_me(event)

        elif path == '/api/auth/refresh' and http_method == 'POST':
            body = json.loads(event.get('body', '{}'))
            return refresh_token(body)

        # User management endpoints
        elif path == '/api/users' and http_method == 'GET':
            return get_users(event, query_params)

        # Role Request endpoints (web-based)
        elif path == '/api/role-requests/options' and http_method == 'GET':
            return get_role_request_options(event)

        elif path == '/api/role-requests/admin' and http_method == 'POST':
            body = json.loads(event.get('body', '{}'))
            return create_admin_role_grant(event, body)

        elif path == '/api/role-requests' and http_method == 'POST':
            body = json.loads(event.get('body', '{}'))
            return create_role_request(event, body)

        # Ticket approval/rejection endpoints (Admin)
        elif path.startswith('/api/tickets/') and path.endswith('/approve') and http_method == 'POST':
            request_id = path.split('/')[3]
            return approve_ticket(event, request_id)

        elif path.startswith('/api/tickets/') and path.endswith('/reject') and http_method == 'POST':
            request_id = path.split('/')[3]
            body = json.loads(event.get('body', '{}'))
            return reject_ticket(event, request_id, body)

        elif path.startswith('/api/tickets/') and path.endswith('/revoke') and http_method == 'POST':
            request_id = path.split('/')[3]
            return revoke_ticket(event, request_id)

        # Tag Config endpoints (admin only)
        elif path == '/api/tags' and http_method == 'GET':
            return get_tags(event, query_params)

        elif path == '/api/tags' and http_method == 'POST':
            body = json.loads(event.get('body', '{}'))
            return create_tag_endpoint(event, body)

        elif path.startswith('/api/tags/') and http_method == 'PUT':
            tag_type = path.split('/')[3]
            tag_value = path.split('/')[4] if len(path.split('/')) > 4 else ''
            body = json.loads(event.get('body', '{}'))
            return update_tag_endpoint(event, tag_type, tag_value, body)

        elif path.startswith('/api/tags/') and http_method == 'DELETE':
            tag_type = path.split('/')[3]
            tag_value = path.split('/')[4] if len(path.split('/')) > 4 else ''
            return delete_tag_endpoint(event, tag_type, tag_value)

        else:
            return response(404, {'error': '요청한 리소스를 찾을 수 없습니다'})

    except Exception as e:
        print(f"[dashboard_api] Error: {e}")
        return response(500, {'error': str(e)})


def get_tickets(query_params: Dict[str, str]) -> Dict[str, Any]:
    """
    GET /api/tickets
    Get list of role requests (tickets), sorted by created_at descending.

    Query params:
    - status: Filter by status (pending, approved, active, expired, etc.)
              If provided, uses StatusCreatedIndex GSI for efficient query.
              If not provided, scans entire table with pagination.
    - user_name: Filter by requester name (client-side after fetch)
    - iam_user_name: Filter by iam_user_name (server-side)
    - limit: Max items to return (default 50)
    """
    status = query_params.get('status')
    user_name = query_params.get('user_name')
    iam_user_name = query_params.get('iam_user_name')
    limit = int(query_params.get('limit', '50'))

    items = []

    if status:
        # status 필터 있음 → GSI Query (created_at DESC)
        query_kwargs = {
            'IndexName': 'StatusCreatedIndex',
            'KeyConditionExpression': Key('status').eq(status),
            'ScanIndexForward': False,  # created_at 내림차순
            'Limit': limit,
        }
        if iam_user_name:
            query_kwargs['FilterExpression'] = Attr('iam_user_name').eq(iam_user_name)

        # FilterExpression은 Limit 이후 적용되므로 충분한 데이터 확보 위해 반복
        while len(items) < limit:
            result = role_requests_table.query(**query_kwargs)
            items.extend(result.get('Items', []))
            if 'LastEvaluatedKey' not in result:
                break
            query_kwargs['ExclusiveStartKey'] = result['LastEvaluatedKey']
    else:
        # status 필터 없음 → 전체 scan (pagination으로 모든 데이터 확보)
        scan_kwargs = {}
        filter_expressions = []
        expression_values = {}

        if iam_user_name:
            filter_expressions.append('iam_user_name = :iam_user_name')
            expression_values[':iam_user_name'] = iam_user_name

        if filter_expressions:
            scan_kwargs['FilterExpression'] = ' AND '.join(filter_expressions)
            scan_kwargs['ExpressionAttributeValues'] = expression_values

        while True:
            result = role_requests_table.scan(**scan_kwargs)
            items.extend(result.get('Items', []))
            if 'LastEvaluatedKey' not in result:
                break
            scan_kwargs['ExclusiveStartKey'] = result['LastEvaluatedKey']

        # created_at 내림차순 정렬
        items.sort(key=lambda x: x.get('created_at', ''), reverse=True)

    # Client-side user_name filter (requester_name contains)
    if user_name:
        items = [
            item for item in items
            if user_name.lower() in item.get('requester_name', '').lower()
        ]

    # limit 적용
    items = items[:limit]

    return response(200, {
        'tickets': items,
        'count': len(items),
    })


def get_ticket_detail(request_id: str) -> Dict[str, Any]:
    """
    GET /api/tickets/{request_id}
    Get ticket detail with activity logs
    """
    # Get ticket from RoleRequests
    ticket_result = role_requests_table.get_item(Key={'request_id': request_id})
    ticket = ticket_result.get('Item')

    if not ticket:
        return response(404, {'error': '티켓을 찾을 수 없습니다'})

    # Get activity logs if role_arn exists
    activities = []
    if ticket.get('role_arn'):
        # Extract role_name from role_arn
        role_arn = ticket['role_arn']
        role_name = role_arn.split('/')[-1] if '/' in role_arn else role_arn

        # Query ActivityLogs by role_name
        activity_result = activity_logs_table.query(
            KeyConditionExpression=Key('role_name').eq(role_name),
            ScanIndexForward=False,  # Descending order by event_time
            Limit=100
        )
        activities = activity_result.get('Items', [])

    # Get linked work request if exists
    work_request = None
    if ticket.get('work_request_id'):
        try:
            wr_result = work_requests_table.get_item(Key={'request_id': ticket['work_request_id']})
            work_request = wr_result.get('Item')
        except Exception as e:
            print(f"[get_ticket_detail] Error fetching work request: {e}")

    return response(200, {
        'ticket': ticket,
        'activities': activities,
        'activity_count': len(activities),
        'work_request': work_request
    })


def get_activities(query_params: Dict[str, str]) -> Dict[str, Any]:
    """
    GET /api/activities
    Get activity logs with filters

    Query params:
    - user_name: Filter by IAM user name
    - start_time: Start time (ISO8601)
    - end_time: End time (ISO8601)
    - event_name: Filter by event name
    - limit: Max items to return (default 100)
    """
    user_name = query_params.get('user_name')
    start_time = query_params.get('start_time')
    end_time = query_params.get('end_time')
    event_name = query_params.get('event_name')
    limit = int(query_params.get('limit', '100'))

    # If user_name provided, use GSI
    if user_name:
        query_kwargs = {
            'IndexName': 'UserNameIndex',
            'KeyConditionExpression': Key('iam_user_name').eq(user_name),
            'ScanIndexForward': False,
            'Limit': limit
        }

        # Add time range filter if provided
        if start_time and end_time:
            query_kwargs['KeyConditionExpression'] = (
                Key('iam_user_name').eq(user_name) &
                Key('event_time').between(start_time, end_time)
            )
        elif start_time:
            query_kwargs['KeyConditionExpression'] = (
                Key('iam_user_name').eq(user_name) &
                Key('event_time').gte(start_time)
            )
        elif end_time:
            query_kwargs['KeyConditionExpression'] = (
                Key('iam_user_name').eq(user_name) &
                Key('event_time').lte(end_time)
            )

        # Add event_name filter (partial match)
        if event_name:
            query_kwargs['FilterExpression'] = Attr('event_name').contains(event_name)

        result = activity_logs_table.query(**query_kwargs)
        items = result.get('Items', [])
    else:
        has_filters = start_time or end_time or event_name

        # Use cache for unfiltered full scan
        if not has_filters:
            now = time.time()
            if _activities_cache['items'] is not None and (now - _activities_cache['timestamp']) < ACTIVITIES_CACHE_TTL:
                return response(200, {
                    'activities': _activities_cache['items'][:limit],
                    'count': min(len(_activities_cache['items']), limit)
                })

        # Scan with pagination
        scan_kwargs = {}

        if has_filters:
            filter_expressions = []
            expression_values = {}

            if start_time:
                filter_expressions.append('event_time >= :start_time')
                expression_values[':start_time'] = start_time

            if end_time:
                filter_expressions.append('event_time <= :end_time')
                expression_values[':end_time'] = end_time

            if event_name:
                filter_expressions.append('contains(event_name, :event_name)')
                expression_values[':event_name'] = event_name

            scan_kwargs['FilterExpression'] = ' AND '.join(filter_expressions)
            scan_kwargs['ExpressionAttributeValues'] = expression_values

        items = []
        while True:
            result = activity_logs_table.scan(**scan_kwargs)
            items.extend(result.get('Items', []))
            if 'LastEvaluatedKey' not in result:
                break
            scan_kwargs['ExclusiveStartKey'] = result['LastEvaluatedKey']

        # Sort by event_time descending
        items.sort(key=lambda x: x.get('event_time', ''), reverse=True)

        # Update cache for unfiltered results
        if not has_filters:
            _activities_cache['items'] = items
            _activities_cache['timestamp'] = time.time()

    # Apply limit
    items = items[:limit]

    return response(200, {
        'activities': items,
        'count': len(items)
    })


def get_user_activities(iam_user_name: str, query_params: Dict[str, str]) -> Dict[str, Any]:
    """
    GET /api/users/{iam_user_name}/activities
    Get activity logs for a specific user
    """
    query_params['user_name'] = iam_user_name
    return get_activities(query_params)


def get_services() -> Dict[str, Any]:
    """
    GET /api/services
    Get list of available services with display names
    """
    valid_services = get_valid_services()
    display_names = get_service_display_names()
    services = []
    for key in valid_services:
        services.append({
            'key': key,
            'name': display_names.get(key, key),
            'display': f"{key} ({display_names.get(key, key)})" if display_names.get(key) else key
        })

    return response(200, {
        'services': services,
        'count': len(services)
    })


def create_work_request(body: Dict[str, Any]) -> Dict[str, Any]:
    """
    POST /api/work-requests
    Create a new work request

    Request body:
    - service_name: Service key (e.g., "safety", "infra")
    - start_date: Work start date (ISO8601)
    - end_date: Work end date (ISO8601)
    - description: Work description
    - requester_name: Name of the requester
    """
    # Validate required fields
    required_fields = ['service_name', 'start_date', 'end_date', 'description', 'requester_name']
    for field in required_fields:
        if not body.get(field):
            return response(400, {'error': f'필수 항목이 누락되었습니다: {field}', 'status': 'error'})

    service_name = body['service_name']

    # Validate service_name
    if service_name not in get_valid_services():
        return response(400, {'error': f'유효하지 않은 서비스명입니다: {service_name}', 'status': 'error'})

    # Generate request ID
    request_id = str(uuid.uuid4())

    # Get current time in KST
    now_kst = datetime.now(KST)
    created_at = now_kst.isoformat()

    # Create work request item
    item = {
        'request_id': request_id,
        'service_name': service_name,
        'service_display_name': get_service_display_names().get(service_name, service_name),
        'start_date': body['start_date'],
        'end_date': body['end_date'],
        'description': body['description'],
        'requester_name': body['requester_name'],
        'created_at': created_at,
        'status': 'pending'
    }

    # Save to DynamoDB
    work_requests_table.put_item(Item=item)

    # Send Mattermost notification
    try:
        if REQUEST_CHANNEL_ID:
            mattermost = MattermostClient()

            # Format dates for display
            start_date_display = body['start_date'][:10] if len(body['start_date']) >= 10 else body['start_date']
            end_date_display = body['end_date'][:10] if len(body['end_date']) >= 10 else body['end_date']

            # Get interactive callback URL
            api_url = os.environ.get('API_URL', '') or "https://ktmbr0kj46.execute-api.ap-northeast-2.amazonaws.com/prod"
            callback_url = f"{api_url}/interactive"

            # Use the same pattern as create_approval_message
            attachment = create_work_request_notification(
                request_id=request_id,
                service_name=get_service_display_names().get(service_name, service_name),
                requester_name=body['requester_name'],
                start_date=start_date_display,
                end_date=end_date_display,
                description=body['description'],
                callback_url=callback_url,
            )

            mattermost.send_interactive_message(
                channel_id=REQUEST_CHANNEL_ID,
                text="📋 새로운 업무 요청이 도착했습니다.",
                attachments=[attachment]
            )
            print(f"[create_work_request] Mattermost notification sent for request: {request_id}")
    except Exception as e:
        # Don't fail the request if Mattermost notification fails
        print(f"[create_work_request] Failed to send Mattermost notification: {e}")

    return response(201, {
        'request_id': request_id,
        'status': 'success',
        'message': '업무 요청이 생성되었습니다'
    })


def update_work_request(request_id: str, body: Dict[str, Any], event: Dict[str, Any]) -> Dict[str, Any]:
    """
    PATCH /api/work-requests/{request_id}
    Update work request status (Admin only)

    Request body:
    - status: New status (pending, in_progress, completed, cancelled)
    """
    # Check if user is admin
    user = get_current_user(event)
    if not user:
        return response(401, {'error': '인증이 필요합니다', 'status': 'error'})

    if not user.get('is_admin', False):
        return response(403, {'error': '권한이 없습니다. 관리자만 상태를 변경할 수 있습니다.', 'status': 'error'})

    new_status = body.get('status')

    if not new_status:
        return response(400, {'error': '상태 값이 누락되었습니다', 'status': 'error'})

    valid_statuses = ['pending', 'in_progress', 'completed', 'cancelled']
    if new_status not in valid_statuses:
        return response(400, {'error': f'유효하지 않은 상태값입니다: {new_status}', 'status': 'error'})

    # Get current time in KST
    now_kst = datetime.now(KST)
    updated_at = now_kst.isoformat()

    # Update in DynamoDB
    try:
        work_requests_table.update_item(
            Key={'request_id': request_id},
            UpdateExpression='SET #status = :status, updated_at = :updated_at',
            ExpressionAttributeNames={'#status': 'status'},
            ExpressionAttributeValues={
                ':status': new_status,
                ':updated_at': updated_at
            }
        )
    except Exception as e:
        return response(500, {'error': str(e), 'status': 'error'})

    return response(200, {
        'request_id': request_id,
        'status': 'success',
        'new_status': new_status,
        'message': '업무 요청 상태가 변경되었습니다'
    })


def get_work_requests(query_params: Dict[str, str]) -> Dict[str, Any]:
    """
    GET /api/work-requests
    Get list of work requests

    Query params:
    - service_name: Filter by service name
    - status: Filter by status
    - limit: Max items to return (default 50)
    """
    service_name = query_params.get('service_name')
    status = query_params.get('status')
    limit = int(query_params.get('limit', '50'))

    # Scan with filters (partial match for service_name)
    scan_kwargs = {
        'Limit': limit
    }

    filter_expressions = []
    expression_values = {}
    expression_names = {}

    if service_name:
        # Partial match on service_name or service_display_name
        filter_expressions.append('(contains(service_name, :service_name) OR contains(service_display_name, :service_name))')
        expression_values[':service_name'] = service_name

    if status:
        filter_expressions.append('#status = :status')
        expression_values[':status'] = status
        expression_names['#status'] = 'status'

    if filter_expressions:
        scan_kwargs['FilterExpression'] = ' AND '.join(filter_expressions)
        scan_kwargs['ExpressionAttributeValues'] = expression_values
        if expression_names:
            scan_kwargs['ExpressionAttributeNames'] = expression_names

    result = work_requests_table.scan(**scan_kwargs)

    items = result.get('Items', [])

    # Sort by created_at descending
    items.sort(key=lambda x: x.get('created_at', ''), reverse=True)

    return response(200, {
        'work_requests': items,
        'count': len(items)
    })


def get_work_request_detail(request_id: str) -> Dict[str, Any]:
    """
    GET /api/work-requests/{request_id}
    Get work request detail with linked tickets
    """
    # Get work request
    try:
        result = work_requests_table.get_item(Key={'request_id': request_id})
        work_request = result.get('Item')
    except Exception as e:
        print(f"[get_work_request_detail] Error: {e}")
        return response(500, {'error': '서버 오류가 발생했습니다'})

    if not work_request:
        return response(404, {'error': '업무 요청을 찾을 수 없습니다'})

    # Get linked tickets
    linked_tickets = []
    try:
        # Scan RoleRequests for tickets linked to this work request
        scan_result = role_requests_table.scan(
            FilterExpression=Attr('work_request_id').eq(request_id)
        )
        linked_tickets = scan_result.get('Items', [])
        # Sort by created_at descending
        linked_tickets.sort(key=lambda x: x.get('created_at', ''), reverse=True)
    except Exception as e:
        print(f"[get_work_request_detail] Error fetching linked tickets: {e}")

    return response(200, {
        'work_request': work_request,
        'linked_tickets': linked_tickets,
        'linked_ticket_count': len(linked_tickets)
    })


def get_work_request_tickets(request_id: str) -> Dict[str, Any]:
    """
    GET /api/work-requests/{request_id}/tickets
    Get all tickets linked to a work request
    """
    try:
        # Scan RoleRequests for tickets linked to this work request
        scan_result = role_requests_table.scan(
            FilterExpression=Attr('work_request_id').eq(request_id)
        )
        tickets = scan_result.get('Items', [])
        # Sort by created_at descending
        tickets.sort(key=lambda x: x.get('created_at', ''), reverse=True)
    except Exception as e:
        print(f"[get_work_request_tickets] Error: {e}")
        return response(500, {'error': '서버 오류가 발생했습니다'})

    return response(200, {
        'tickets': tickets,
        'count': len(tickets)
    })


def update_ticket(request_id: str, body: Dict[str, Any], event: Dict[str, Any]) -> Dict[str, Any]:
    """
    PATCH /api/tickets/{request_id}
    Update ticket (link to work request)

    Request body:
    - work_request_id: ID of work request to link (or null to unlink)
    """
    # Check authentication
    user = get_current_user(event)
    if not user:
        return response(401, {'error': '인증이 필요합니다'})

    # Check if ticket exists
    try:
        result = role_requests_table.get_item(Key={'request_id': request_id})
        ticket = result.get('Item')
    except Exception as e:
        print(f"[update_ticket] Error fetching ticket: {e}")
        return response(500, {'error': '서버 오류가 발생했습니다'})

    if not ticket:
        return response(404, {'error': '티켓을 찾을 수 없습니다'})

    work_request_id = body.get('work_request_id')

    # If linking to a work request, verify it exists
    if work_request_id:
        try:
            wr_result = work_requests_table.get_item(Key={'request_id': work_request_id})
            if not wr_result.get('Item'):
                return response(404, {'error': '업무 요청을 찾을 수 없습니다'})
        except Exception as e:
            print(f"[update_ticket] Error fetching work request: {e}")
            return response(500, {'error': '서버 오류가 발생했습니다'})

    # Update ticket
    now_kst = datetime.now(KST)
    try:
        if work_request_id:
            role_requests_table.update_item(
                Key={'request_id': request_id},
                UpdateExpression='SET work_request_id = :wrid, updated_at = :updated_at',
                ExpressionAttributeValues={
                    ':wrid': work_request_id,
                    ':updated_at': now_kst.isoformat()
                }
            )
        else:
            # Remove the link
            role_requests_table.update_item(
                Key={'request_id': request_id},
                UpdateExpression='REMOVE work_request_id SET updated_at = :updated_at',
                ExpressionAttributeValues={
                    ':updated_at': now_kst.isoformat()
                }
            )
    except Exception as e:
        print(f"[update_ticket] Error updating ticket: {e}")
        return response(500, {'error': '서버 오류가 발생했습니다'})

    return response(200, {
        'request_id': request_id,
        'work_request_id': work_request_id,
        'message': '업무 요청 연결이 변경되었습니다' if work_request_id else '업무 요청 연결이 해제되었습니다'
    })


def get_api_keys(event: Dict[str, Any]) -> Dict[str, Any]:
    """
    GET /api/api-keys
    Get list of API keys (admin only)
    Returns key metadata without the actual key
    """
    # TODO: Add proper admin authentication when JWT is implemented
    # For now, this endpoint is accessible but returns masked keys

    try:
        result = api_keys_table.scan()
        items = result.get('Items', [])

        # Mask the actual key hashes and return only metadata
        keys = []
        for item in items:
            keys.append({
                'key_id': item.get('key_id'),
                'name': item.get('name'),
                'description': item.get('description'),
                'status': item.get('status'),
                'created_at': item.get('created_at'),
                'expires_at': item.get('expires_at'),
                'last_used_at': item.get('last_used_at'),
                'created_by': item.get('created_by')
            })

        # Sort by created_at descending
        keys.sort(key=lambda x: x.get('created_at', ''), reverse=True)

        return response(200, {
            'api_keys': keys,
            'count': len(keys)
        })
    except Exception as e:
        print(f"[get_api_keys] Error: {e}")
        return response(500, {'error': str(e)})


def create_api_key(event: Dict[str, Any], body: Dict[str, Any]) -> Dict[str, Any]:
    """
    POST /api/api-keys
    Create a new API key (admin only)

    Request body:
    - name: Key name (required)
    - description: Key description (optional)
    - expires_in_days: Days until expiration (optional, default: no expiration)
    """
    # TODO: Add proper admin authentication when JWT is implemented

    name = body.get('name')
    if not name:
        return response(400, {'error': '필수 항목이 누락되었습니다: name'})

    description = body.get('description', '')
    expires_in_days = body.get('expires_in_days')

    # Generate new API key
    raw_api_key = generate_api_key()
    hashed_key = hash_api_key(raw_api_key)
    key_id = str(uuid.uuid4())

    # Get current time in KST
    now_kst = datetime.now(KST)
    created_at = now_kst.isoformat()

    # Calculate expiration if specified
    expires_at = None
    if expires_in_days:
        expires_at = (now_kst + timedelta(days=int(expires_in_days))).isoformat()

    # Create API key item
    item = {
        'api_key': hashed_key,  # Store hashed key as primary key
        'key_id': key_id,       # Unique ID for reference
        'name': name,
        'description': description,
        'status': 'active',
        'created_at': created_at,
        'expires_at': expires_at,
        'created_by': 'admin'   # TODO: Get from JWT when implemented
    }

    try:
        api_keys_table.put_item(Item=item)

        return response(201, {
            'key_id': key_id,
            'api_key': raw_api_key,  # Return raw key only on creation
            'name': name,
            'expires_at': expires_at,
            'message': 'API Key가 생성되었습니다. 이 키는 다시 표시되지 않으니 반드시 저장하세요.'
        })
    except Exception as e:
        print(f"[create_api_key] Error: {e}")
        return response(500, {'error': str(e)})


def revoke_api_key(event: Dict[str, Any], key_id: str) -> Dict[str, Any]:
    """
    DELETE /api/api-keys/{key_id}
    Revoke (deactivate) an API key (admin only)
    """
    # TODO: Add proper admin authentication when JWT is implemented

    try:
        # Find the key by key_id
        result = api_keys_table.scan(
            FilterExpression=Attr('key_id').eq(key_id)
        )
        items = result.get('Items', [])

        if not items:
            return response(404, {'error': 'API Key를 찾을 수 없습니다'})

        key_item = items[0]
        hashed_key = key_item['api_key']

        # Update status to revoked
        now_kst = datetime.now(KST)
        api_keys_table.update_item(
            Key={'api_key': hashed_key},
            UpdateExpression='SET #status = :status, revoked_at = :revoked_at',
            ExpressionAttributeNames={'#status': 'status'},
            ExpressionAttributeValues={
                ':status': 'revoked',
                ':revoked_at': now_kst.isoformat()
            }
        )

        return response(200, {
            'key_id': key_id,
            'status': 'revoked',
            'message': 'API Key가 취소되었습니다'
        })
    except Exception as e:
        print(f"[revoke_api_key] Error: {e}")
        return response(500, {'error': str(e)})


def verify_api_key_endpoint(event: Dict[str, Any]) -> Dict[str, Any]:
    """
    GET /api/verify-key
    Verify if the provided API key is valid
    Returns key info if valid
    """
    key_info = require_api_key(event)

    if not key_info:
        return response(401, {
            'valid': False,
            'error': '유효하지 않거나 만료된 API Key입니다'
        })

    # Update last_used_at
    try:
        now_kst = datetime.now(KST)
        api_keys_table.update_item(
            Key={'api_key': key_info['api_key']},
            UpdateExpression='SET last_used_at = :last_used_at',
            ExpressionAttributeValues={
                ':last_used_at': now_kst.isoformat()
            }
        )
    except Exception as e:
        print(f"[verify_api_key_endpoint] Error updating last_used_at: {e}")

    return response(200, {
        'valid': True,
        'key_id': key_info.get('key_id'),
        'name': key_info.get('name'),
        'expires_at': key_info.get('expires_at')
    })


# ========== Authentication Endpoints ==========

def login(body: Dict[str, Any]) -> Dict[str, Any]:
    """
    POST /api/auth/login
    Authenticate user and return JWT tokens

    Request body:
    - user_id: Employee ID (e.g., "N1104365")
    - password: Password (verified against SKONS)
    """
    user_id = body.get('user_id', '').strip()
    password = body.get('password', '')

    if not user_id or not password:
        return response(400, {'error': '사번과 비밀번호를 입력해주세요'})

    # Check if user exists in our database
    try:
        result = users_table.get_item(Key={'user_id': user_id})
        user = result.get('Item')
    except Exception as e:
        print(f"[login] Error fetching user: {e}")
        return response(500, {'error': '서버 오류가 발생했습니다'})

    if not user:
        return response(401, {'error': '인증 정보가 올바르지 않습니다'})

    if not user.get('is_active', True):
        return response(401, {'error': '비활성화된 계정입니다'})

    # Test users bypass (test1/test1, test2/test2)
    TEST_USERS = {
        'test1': 'test1',
        'test2': 'test2',
    }

    is_test_user = user_id in TEST_USERS and password == TEST_USERS[user_id]

    # Authenticate with SKONS (skip for test users)
    if not is_test_user and not authenticate_with_skons(user_id, password):
        return response(401, {'error': '인증 정보가 올바르지 않습니다'})

    # Update last_login
    now_kst = datetime.now(KST)
    try:
        users_table.update_item(
            Key={'user_id': user_id},
            UpdateExpression='SET last_login = :last_login',
            ExpressionAttributeValues={
                ':last_login': now_kst.isoformat()
            }
        )
    except Exception as e:
        print(f"[login] Error updating last_login: {e}")

    # Generate tokens
    is_admin = user.get('is_admin', False)
    access_token = create_access_token(user_id, is_admin)
    refresh_token_str = create_refresh_token(user_id)

    return response(200, {
        'access_token': access_token,
        'refresh_token': refresh_token_str,
        'token_type': 'Bearer',
        'expires_in': JWT_ACCESS_TOKEN_EXPIRE_MINUTES * 60,
        'user': {
            'user_id': user.get('user_id'),
            'name': user.get('name'),
            'email': user.get('email'),
            'team': user.get('team'),
            'region': user.get('region'),
            'is_admin': is_admin,
            'iam_user_name': user.get('iam_user_name', ''),
            'mattermost_id': user.get('mattermost_id', '')
        }
    })


def get_me(event: Dict[str, Any]) -> Dict[str, Any]:
    """
    GET /api/auth/me
    Get current user info from JWT token
    """
    user = get_current_user(event)

    if not user:
        return response(401, {'error': '인증이 필요합니다'})

    return response(200, {
        'user': {
            'user_id': user.get('user_id'),
            'name': user.get('name'),
            'email': user.get('email'),
            'phone_number': user.get('phone_number'),
            'team': user.get('team'),
            'region': user.get('region'),
            'job_title': user.get('job_title'),
            'is_admin': user.get('is_admin', False),
            'last_login': user.get('last_login'),
            'created_at': user.get('created_at'),
            'iam_user_name': user.get('iam_user_name', ''),
            'mattermost_id': user.get('mattermost_id', '')
        }
    })


def refresh_token(body: Dict[str, Any]) -> Dict[str, Any]:
    """
    POST /api/auth/refresh
    Refresh access token using refresh token

    Request body:
    - refresh_token: The refresh token
    """
    refresh_token_str = body.get('refresh_token', '')

    if not refresh_token_str:
        return response(400, {'error': 'refresh_token이 필요합니다'})

    # Verify refresh token
    payload = verify_jwt_token(refresh_token_str, 'refresh')
    if not payload:
        return response(401, {'error': '유효하지 않거나 만료된 토큰입니다'})

    user_id = payload.get('sub')

    # Get user to check if still active and get is_admin
    try:
        result = users_table.get_item(Key={'user_id': user_id})
        user = result.get('Item')
    except Exception as e:
        print(f"[refresh_token] Error fetching user: {e}")
        return response(500, {'error': '서버 오류가 발생했습니다'})

    if not user or not user.get('is_active', True):
        return response(401, {'error': '사용자를 찾을 수 없거나 비활성화된 계정입니다'})

    # Generate new access token
    is_admin = user.get('is_admin', False)
    new_access_token = create_access_token(user_id, is_admin)

    return response(200, {
        'access_token': new_access_token,
        'token_type': 'Bearer',
        'expires_in': JWT_ACCESS_TOKEN_EXPIRE_MINUTES * 60
    })


def get_users(event: Dict[str, Any], query_params: Dict[str, str]) -> Dict[str, Any]:
    """
    GET /api/users
    Get list of users (admin only)

    Query params:
    - team: Filter by team
    - limit: Max items to return (default 100)
    """
    # Check if user is admin
    current_user = get_current_user(event)
    if not current_user or not current_user.get('is_admin', False):
        return response(403, {'error': '관리자 권한이 필요합니다'})

    team = query_params.get('team')
    limit = int(query_params.get('limit', '100'))

    try:
        if team:
            # Query by team using GSI
            result = users_table.query(
                IndexName='TeamIndex',
                KeyConditionExpression=Key('team').eq(team),
                Limit=limit
            )
        else:
            # Scan all users
            result = users_table.scan(Limit=limit)

        items = result.get('Items', [])

        # Remove sensitive fields and sort
        users = []
        for item in items:
            users.append({
                'user_id': item.get('user_id'),
                'name': item.get('name'),
                'email': item.get('email'),
                'team': item.get('team'),
                'region': item.get('region'),
                'job_title': item.get('job_title'),
                'is_admin': item.get('is_admin', False),
                'is_active': item.get('is_active', True),
                'last_login': item.get('last_login'),
                'created_at': item.get('created_at')
            })

        users.sort(key=lambda x: x.get('name', ''))

        return response(200, {
            'users': users,
            'count': len(users)
        })
    except Exception as e:
        print(f"[get_users] Error: {e}")
        return response(500, {'error': str(e)})


# ========== Role Request Endpoints (Web-based) ==========

def get_role_request_options(event: Dict[str, Any]) -> Dict[str, Any]:
    """
    GET /api/role-requests/options
    Get form options for role request (env, service, permission_type, target_services, work_requests)
    """
    # Check authentication
    user = get_current_user(event)
    if not user:
        return response(401, {'error': '인증이 필요합니다'})

    # Permission type options
    permission_types = [
        {'value': 'read_only', 'label': '조회만 (Read Only)'},
        {'value': 'read_update', 'label': '조회 + 수정 (Read + Update)'},
        {'value': 'read_update_create', 'label': '조회 + 수정 + 생성', 'admin_only': True},
        {'value': 'full', 'label': '전체 (Full - 삭제 포함)', 'admin_only': True},
    ]

    # Target service options
    target_services = [
        {'value': 'ec2', 'label': 'EC2'},
        {'value': 'rds', 'label': 'RDS'},
        {'value': 'lambda', 'label': 'Lambda'},
        {'value': 's3', 'label': 'S3'},
        {'value': 'elasticbeanstalk', 'label': 'ElasticBeanstalk'},
        {'value': 'dynamodb', 'label': 'DynamoDB'},
        {'value': 'elasticloadbalancing', 'label': 'ELB (로드밸런서)'},
        {'value': 'route53', 'label': 'Route53 (DNS)'},
        {'value': 'amplify', 'label': 'Amplify (웹 호스팅)'},
        {'value': 'billing', 'label': 'Billing (비용 조회)'},
        {'value': 'ecr', 'label': 'ECR (컨테이너 레지스트리)'},
        {'value': 'eks', 'label': 'EKS (쿠버네티스)'},
    ]

    # Environment options
    envs = [{'value': env, 'label': env} for env in get_valid_envs()]

    # Service options
    display_names = get_service_display_names()
    services = [
        {
            'value': svc,
            'label': f"{svc} ({display_names.get(svc, svc)})" if display_names.get(svc) else svc
        }
        for svc in get_valid_services()
    ]

    # Get active work requests for dropdown
    work_requests = []
    try:
        result = work_requests_table.scan(Limit=50)
        items = result.get('Items', [])
        active_items = [
            item for item in items
            if item.get('status') in ['pending', 'in_progress']
        ]
        active_items.sort(key=lambda x: x.get('created_at', ''), reverse=True)

        for item in active_items[:20]:
            service_display = item.get('service_display_name', item.get('service_name', ''))
            description = item.get('description', '')[:30]
            requester = item.get('requester_name', '')
            work_requests.append({
                'value': item.get('request_id', ''),
                'label': f"[{service_display}] {description}... ({requester})",
            })
    except Exception as e:
        print(f"[get_role_request_options] Error fetching work requests: {e}")

    # Get team members list from TeamMembers table
    users_list = []
    try:
        result = team_members_table.scan()
        items = result.get('Items', [])
        for item in items:
            users_list.append({
                'user_id': item.get('user_id'),
                'name': item.get('name'),
                'iam_user_name': item.get('iam_user_name', ''),
                'mattermost_id': item.get('mattermost_id', ''),
            })
        users_list.sort(key=lambda x: x.get('name', ''))
    except Exception as e:
        print(f"[get_role_request_options] Error fetching team members: {e}")

    return response(200, {
        'envs': envs,
        'services': services,
        'permission_types': permission_types,
        'target_services': target_services,
        'work_requests': work_requests,
        'users': users_list,
    })


def create_role_request(event: Dict[str, Any], body: Dict[str, Any]) -> Dict[str, Any]:
    """
    POST /api/role-requests
    Create a new role request (normal user)
    """
    # Check authentication
    user = get_current_user(event)
    if not user:
        return response(401, {'error': '인증이 필요합니다'})

    # Extract fields
    iam_user_name = body.get('iam_user_name', '').strip()
    env = body.get('env', '')
    service = body.get('service', '')
    permission_type = body.get('permission_type', 'read_update')
    target_services_raw = body.get('target_services', ['all'])
    if isinstance(target_services_raw, str):
        target_services_list = [target_services_raw] if target_services_raw else ['all']
    elif isinstance(target_services_raw, list):
        target_services_list = target_services_raw if target_services_raw else ['all']
    else:
        target_services_list = ['all']
    start_time_str = body.get('start_time', '').strip()
    end_time_str = body.get('end_time', '').strip()
    purpose = body.get('purpose', '').strip()
    work_request_id = body.get('work_request_id', '').strip() or None
    include_parameter_store = body.get('include_parameter_store', False)
    include_secrets_manager = body.get('include_secrets_manager', False)

    # If iam_user_name is not provided, use user's iam_user_name
    if not iam_user_name:
        iam_user_name = user.get('iam_user_name', '')
        if not iam_user_name:
            return response(400, {'error': 'IAM 사용자명이 필요합니다. 관리자에게 문의하세요.'})

    # Billing 단독 요청 판별
    is_billing_only = (
        isinstance(target_services_list, list)
        and len(target_services_list) == 1
        and target_services_list[0] == 'billing'
    )

    # Validate required fields (billing 단독 시 env/service 스킵)
    if not is_billing_only and not env:
        return response(400, {'error': 'Environment를 선택해주세요'})
    if not is_billing_only and not service:
        return response(400, {'error': 'Service를 선택해주세요'})
    if not end_time_str:
        return response(400, {'error': '종료 시간을 입력해주세요'})
    if not purpose:
        return response(400, {'error': '목적을 입력해주세요'})

    # Parse times
    now_kst = datetime.now(KST)

    try:
        if start_time_str:
            start_time = datetime.fromisoformat(start_time_str.replace('Z', '+00:00'))
            if start_time.tzinfo:
                start_time = start_time.replace(tzinfo=None)
        else:
            start_time = datetime(now_kst.year, now_kst.month, now_kst.day, now_kst.hour, now_kst.minute)

        end_time = datetime.fromisoformat(end_time_str.replace('Z', '+00:00'))
        if end_time.tzinfo:
            end_time = end_time.replace(tzinfo=None)
    except ValueError as e:
        return response(400, {'error': f'시간 형식이 올바르지 않습니다: {str(e)}'})

    # Validate time range
    if end_time <= start_time:
        return response(400, {'error': '종료 시간은 시작 시간보다 이후여야 합니다'})

    # Validate using RequestValidator
    validator = RequestValidator()
    validation_result = validator.validate(
        iam_user_name=iam_user_name,
        env=env,
        service=service,
        start_time=start_time,
        end_time=end_time,
        purpose=purpose,
        target_services=target_services_list,
    )

    if not validation_result.is_valid:
        error_messages = ", ".join([e.message for e in validation_result.errors])
        return response(400, {'error': error_messages})

    # Validate IAM user exists
    iam_validation = validator.validate_iam_user_exists(iam_user_name)
    if not iam_validation.is_valid:
        error_messages = ", ".join([e.message for e in iam_validation.errors])
        return response(400, {'error': error_messages})

    # Generate request ID
    request_id = str(uuid.uuid4())

    # Get requester's mattermost_id from TeamMembers table
    requester_mattermost_id = ''
    try:
        # TeamMembers 테이블에서 iam_user_name으로 검색
        tm_result = team_members_table.scan(
            FilterExpression=Attr('iam_user_name').eq(iam_user_name)
        )
        tm_items = tm_result.get('Items', [])
        if tm_items:
            requester_mattermost_id = tm_items[0].get('mattermost_id', '')
            print(f"[create_role_request] Found mattermost_id: {requester_mattermost_id} for {iam_user_name}")
    except Exception as e:
        print(f"[create_role_request] Error fetching mattermost_id: {e}")

    # Create RoleRequest object
    role_request = RoleRequest(
        request_id=request_id,
        requester_mattermost_id=requester_mattermost_id,
        requester_name=user.get('name', ''),
        iam_user_name=iam_user_name,
        env=env,
        service=service,
        start_time=start_time,
        end_time=end_time,
        purpose=purpose,
        permission_type=permission_type,
        target_services=target_services_list,
        status=RequestStatus.PENDING,
        work_request_id=work_request_id,
        include_parameter_store=include_parameter_store,
        include_secrets_manager=include_secrets_manager,
    )

    # Save to DynamoDB
    try:
        role_requests_table.put_item(Item=role_request.to_dict())
    except Exception as e:
        print(f"[create_role_request] Error saving: {e}")
        return response(500, {'error': '요청 저장 중 오류가 발생했습니다'})

    # Send notifications via notification_service
    try:
        mattermost = MattermostClient()
        request_context = event.get('requestContext', {})
        domain_name = request_context.get('domainName', '')
        stage = request_context.get('stage', 'prod')
        callback_url = f"https://{domain_name}/{stage}/interactive" if domain_name else (f"{API_URL}/interactive" if API_URL else "")

        post_id = notify_request_created(
            mattermost=mattermost,
            request_id=request_id,
            requester_name=user.get('name', ''),
            requester_mattermost_id=requester_mattermost_id,
            iam_user_name=iam_user_name,
            env=env,
            service=service,
            start_time=start_time,
            end_time=end_time,
            purpose=purpose,
            permission_type=permission_type,
            target_services=target_services_list,
            callback_url=callback_url,
            source="웹",
            include_parameter_store=include_parameter_store,
            include_secrets_manager=include_secrets_manager,
        )
        if post_id:
            role_requests_table.update_item(
                Key={'request_id': request_id},
                UpdateExpression='SET post_id = :post_id',
                ExpressionAttributeValues={':post_id': post_id}
            )
    except Exception as e:
        print(f"[create_role_request] Failed to send Mattermost notification: {e}")

    return response(201, {
        'request_id': request_id,
        'status': 'success',
        'message': '권한 요청이 제출되었습니다. 승인 후 알림을 받으실 수 있습니다.'
    })


def create_admin_role_grant(event: Dict[str, Any], body: Dict[str, Any]) -> Dict[str, Any]:
    """
    POST /api/role-requests/admin
    Create and immediately grant role (admin only)
    """
    # Check authentication
    user = get_current_user(event)
    if not user:
        return response(401, {'error': '인증이 필요합니다'})

    # Check admin permission
    if not user.get('is_admin', False):
        return response(403, {'error': '관리자 권한이 필요합니다'})

    # Extract fields
    target_user_id = body.get('target_user_id', '').strip()
    iam_user_name = body.get('iam_user_name', '').strip()
    env = body.get('env', '')
    service = body.get('service', '')
    permission_type = body.get('permission_type', 'read_update')
    target_services_raw = body.get('target_services', ['all'])
    if isinstance(target_services_raw, str):
        target_services_list = [target_services_raw] if target_services_raw else ['all']
    elif isinstance(target_services_raw, list):
        target_services_list = target_services_raw if target_services_raw else ['all']
    else:
        target_services_list = ['all']
    start_time_str = body.get('start_time', '').strip()
    end_time_str = body.get('end_time', '').strip()
    purpose = body.get('purpose', '').strip()
    work_request_id = body.get('work_request_id', '').strip() or None
    include_parameter_store = body.get('include_parameter_store', False)
    include_secrets_manager = body.get('include_secrets_manager', False)

    # Validate required fields
    if not target_user_id:
        return response(400, {'error': '대상 사용자를 선택해주세요'})
    if not env:
        return response(400, {'error': 'Environment를 선택해주세요'})
    if not service:
        return response(400, {'error': 'Service를 선택해주세요'})
    if not end_time_str:
        return response(400, {'error': '종료 시간을 입력해주세요'})
    if not purpose:
        return response(400, {'error': '목적을 입력해주세요'})

    # Get target user info from TeamMembers table
    try:
        result = team_members_table.get_item(Key={'user_id': target_user_id})
        target_user = result.get('Item')
    except Exception as e:
        print(f"[create_admin_role_grant] Error fetching target user: {e}")
        return response(500, {'error': '대상 사용자 조회 중 오류가 발생했습니다'})

    if not target_user:
        return response(404, {'error': '대상 사용자를 찾을 수 없습니다 (TeamMembers 테이블에 없음)'})

    # Use target user's iam_user_name if not provided
    if not iam_user_name:
        iam_user_name = target_user.get('iam_user_name', '')
        if not iam_user_name:
            return response(400, {'error': '대상 사용자의 IAM 사용자명이 설정되지 않았습니다'})

    target_mattermost_id = target_user.get('mattermost_id', '')

    # Parse times
    now_kst = datetime.now(KST)

    try:
        if start_time_str:
            start_time = datetime.fromisoformat(start_time_str.replace('Z', '+00:00'))
            if start_time.tzinfo:
                start_time = start_time.replace(tzinfo=None)
        else:
            start_time = datetime(now_kst.year, now_kst.month, now_kst.day, now_kst.hour, now_kst.minute)

        end_time = datetime.fromisoformat(end_time_str.replace('Z', '+00:00'))
        if end_time.tzinfo:
            end_time = end_time.replace(tzinfo=None)
    except ValueError as e:
        return response(400, {'error': f'시간 형식이 올바르지 않습니다: {str(e)}'})

    # Validate time range
    if end_time <= start_time:
        return response(400, {'error': '종료 시간은 시작 시간보다 이후여야 합니다'})

    # Validate using RequestValidator
    validator = RequestValidator()
    validation_result = validator.validate(
        iam_user_name=iam_user_name,
        env=env,
        service=service,
        start_time=start_time,
        end_time=end_time,
        purpose=purpose,
        is_master_request=True,
    )

    if not validation_result.is_valid:
        error_messages = ", ".join([e.message for e in validation_result.errors])
        return response(400, {'error': error_messages})

    # Validate IAM user exists
    iam_validation = validator.validate_iam_user_exists(iam_user_name)
    if not iam_validation.is_valid:
        error_messages = ", ".join([e.message for e in iam_validation.errors])
        return response(400, {'error': error_messages})

    # Generate request ID
    request_id = str(uuid.uuid4())

    # Create RoleRequest object
    role_request = RoleRequest(
        request_id=request_id,
        requester_mattermost_id=target_mattermost_id,
        requester_name=target_user.get('name', ''),
        iam_user_name=iam_user_name,
        env=env,
        service=service,
        start_time=start_time,
        end_time=end_time,
        purpose=purpose,
        permission_type=permission_type,
        target_services=target_services_list,
        status=RequestStatus.APPROVED,
        approver_id=user.get('user_id'),
        is_master_request=True,
        work_request_id=work_request_id,
        include_parameter_store=include_parameter_store,
        include_secrets_manager=include_secrets_manager,
    )

    # Create IAM Role immediately
    try:
        from services.role_manager import RoleManager
        from services.scheduler import Scheduler

        role_manager = RoleManager()
        scheduler = Scheduler()

        # Create role
        role_info = role_manager.create_dynamic_role(role_request)
        role_request.role_arn = role_info.get('role_arn')
        role_request.policy_arn = role_info.get('policy_arn')
        role_request.status = RequestStatus.ACTIVE

        # Schedule deletion
        scheduler.create_end_schedule(role_request)

        # Save to DynamoDB
        role_requests_table.put_item(Item=role_request.to_dict())

        # Send DM to target user via notification_service
        if target_mattermost_id:
            try:
                mattermost = MattermostClient()
                notify_role_created(
                    mattermost=mattermost,
                    request_id=request_id,
                    requester_mattermost_id=target_mattermost_id,
                    iam_user_name=iam_user_name,
                    env=env,
                    service=service,
                    start_time_str=start_time.strftime('%Y-%m-%d %H:%M'),
                    end_time_str=end_time.strftime('%Y-%m-%d %H:%M'),
                    role_arn=role_request.role_arn,
                    permission_type=permission_type,
                    target_services=target_services_list,
                    source="관리자 즉시 부여",
                    include_parameter_store=include_parameter_store,
                    include_secrets_manager=include_secrets_manager,
                )
            except Exception as e:
                print(f"[create_admin_role_grant] Failed to send DM: {e}")

        return response(201, {
            'request_id': request_id,
            'role_arn': role_request.role_arn,
            'role_name': role_info.get('role_name'),
            'status': 'success',
            'message': 'AWS Role이 즉시 생성되었습니다'
        })

    except Exception as e:
        print(f"[create_admin_role_grant] Error creating role: {e}")
        # Save the request with error status
        role_request.status = RequestStatus.ERROR
        try:
            role_requests_table.put_item(Item=role_request.to_dict())
        except Exception as save_error:
            print(f"[create_admin_role_grant] Error saving error state: {save_error}")

        return response(500, {'error': f'Role 생성 중 오류가 발생했습니다: {str(e)}'})


# ========== Ticket Approval/Rejection Endpoints (Admin) ==========

def get_mattermost_id_for_ticket(ticket: Dict[str, Any]) -> str:
    """
    Get mattermost_id for a ticket.
    First tries ticket's requester_mattermost_id, then looks up in TeamMembers by iam_user_name.
    """
    mattermost_id = ticket.get('requester_mattermost_id', '')
    if mattermost_id:
        return mattermost_id

    # Fallback: look up in TeamMembers by iam_user_name
    iam_user_name = ticket.get('iam_user_name', '')
    if iam_user_name:
        try:
            tm_result = team_members_table.scan(
                FilterExpression=Attr('iam_user_name').eq(iam_user_name)
            )
            tm_items = tm_result.get('Items', [])
            if tm_items:
                mattermost_id = tm_items[0].get('mattermost_id', '')
                print(f"[get_mattermost_id_for_ticket] Found mattermost_id: {mattermost_id} for {iam_user_name}")
        except Exception as e:
            print(f"[get_mattermost_id_for_ticket] Error: {e}")

    return mattermost_id


def approve_ticket(event: Dict[str, Any], request_id: str) -> Dict[str, Any]:
    """
    POST /api/tickets/{request_id}/approve
    Approve a pending ticket (Admin only)
    """
    # Check authentication
    user = get_current_user(event)
    if not user:
        return response(401, {'error': '인증이 필요합니다'})

    # Check admin permission
    if not user.get('is_admin', False):
        return response(403, {'error': '관리자 권한이 필요합니다'})

    # Get ticket
    try:
        result = role_requests_table.get_item(Key={'request_id': request_id})
        ticket = result.get('Item')
    except Exception as e:
        print(f"[approve_ticket] Error fetching ticket: {e}")
        return response(500, {'error': '서버 오류가 발생했습니다'})

    if not ticket:
        return response(404, {'error': '티켓을 찾을 수 없습니다'})

    # Check status
    if ticket.get('status') != 'pending':
        return response(400, {'error': f'현재 상태({ticket.get("status")})에서는 승인할 수 없습니다'})

    # Parse times
    now_kst = datetime.now(KST)

    try:
        start_time_str = ticket.get('start_time', '')
        end_time_str = ticket.get('end_time', '')

        start_time = datetime.fromisoformat(start_time_str.replace('Z', '+00:00')) if start_time_str else now_kst
        end_time = datetime.fromisoformat(end_time_str.replace('Z', '+00:00')) if end_time_str else None

        if start_time.tzinfo:
            start_time = start_time.replace(tzinfo=None)
        if end_time and end_time.tzinfo:
            end_time = end_time.replace(tzinfo=None)
    except Exception as e:
        print(f"[approve_ticket] Error parsing times: {e}")
        return response(500, {'error': '시간 파싱 중 오류가 발생했습니다'})

    # Check if end time is in the past
    now_naive = datetime(now_kst.year, now_kst.month, now_kst.day, now_kst.hour, now_kst.minute, now_kst.second)
    if end_time and end_time <= now_naive:
        return response(400, {'error': '종료 시간이 이미 지났습니다. 새로운 요청을 해주세요.'})

    # Create RoleRequest object for RoleManager
    role_request = RoleRequest(
        request_id=request_id,
        requester_mattermost_id=ticket.get('requester_mattermost_id', ''),
        requester_name=ticket.get('requester_name', ''),
        iam_user_name=ticket.get('iam_user_name', ''),
        env=ticket.get('env', ''),
        service=ticket.get('service', ''),
        start_time=start_time,
        end_time=end_time,
        purpose=ticket.get('purpose', ''),
        permission_type=ticket.get('permission_type', 'read_update'),
        target_services=ticket.get('target_services', ['all']),
        status=RequestStatus.APPROVED,
        work_request_id=ticket.get('work_request_id'),
    )

    # Check if start time is in the past (create role immediately)
    if start_time <= now_naive:
        try:
            from services.role_manager import RoleManager
            from services.scheduler import Scheduler

            role_manager = RoleManager()
            scheduler = Scheduler()

            # Create role
            role_info = role_manager.create_dynamic_role(role_request)

            # Update status to active
            role_requests_table.update_item(
                Key={'request_id': request_id},
                UpdateExpression='SET #status = :status, approver_id = :approver_id, role_arn = :role_arn, policy_arn = :policy_arn, updated_at = :updated_at',
                ExpressionAttributeNames={'#status': 'status'},
                ExpressionAttributeValues={
                    ':status': 'active',
                    ':approver_id': user.get('user_id'),
                    ':role_arn': role_info.get('role_arn'),
                    ':policy_arn': role_info.get('policy_arn'),
                    ':updated_at': now_kst.isoformat()
                }
            )

            # Schedule deletion
            role_request.role_arn = role_info.get('role_arn')
            role_request.policy_arn = role_info.get('policy_arn')
            scheduler.create_end_schedule(role_request)

            # Update linked work request status to in_progress if exists
            if ticket.get('work_request_id'):
                try:
                    wr_result = work_requests_table.get_item(Key={'request_id': ticket['work_request_id']})
                    work_request = wr_result.get('Item')
                    if work_request and work_request.get('status') == 'pending':
                        work_requests_table.update_item(
                            Key={'request_id': ticket['work_request_id']},
                            UpdateExpression='SET #status = :status, updated_at = :updated_at',
                            ExpressionAttributeNames={'#status': 'status'},
                            ExpressionAttributeValues={
                                ':status': 'in_progress',
                                ':updated_at': now_kst.isoformat()
                            }
                        )
                except Exception as e:
                    print(f"[approve_ticket] Error updating work request: {e}")

            # Send all notifications via notification_service
            requester_mattermost_id = get_mattermost_id_for_ticket(ticket)
            callback_url = os.environ.get("CALLBACK_URL", "")
            try:
                mattermost = MattermostClient()
                notify_approved(
                    mattermost=mattermost,
                    request_id=request_id,
                    requester_name=ticket.get('requester_name', ''),
                    requester_mattermost_id=requester_mattermost_id,
                    iam_user_name=ticket.get('iam_user_name', ''),
                    env=ticket.get('env', ''),
                    service=ticket.get('service', ''),
                    start_time_str=start_time.strftime('%Y-%m-%d %H:%M'),
                    end_time_str=end_time.strftime('%Y-%m-%d %H:%M'),
                    approver_name=user.get('name', ''),
                    permission_type=ticket.get('permission_type', 'read_update'),
                    target_services=ticket.get('target_services', ['all']),
                    role_arn=role_info.get('role_arn'),
                    callback_url=callback_url,
                    post_id=ticket.get('post_id'),
                    is_scheduled=False,
                    source="웹",
                    include_parameter_store=ticket.get('include_parameter_store', False),
                    include_secrets_manager=ticket.get('include_secrets_manager', False),
                )
            except Exception as e:
                print(f"[approve_ticket] Failed to send notifications: {e}")

            return response(200, {
                'request_id': request_id,
                'status': 'active',
                'role_arn': role_info.get('role_arn'),
                'message': '승인 완료 - Role이 즉시 생성되었습니다'
            })

        except Exception as e:
            print(f"[approve_ticket] Error creating role: {e}")
            return response(500, {'error': f'Role 생성 중 오류가 발생했습니다: {str(e)}'})

    else:
        # Start time is in the future, create schedules
        try:
            from services.scheduler import Scheduler

            scheduler = Scheduler()

            # Update status to approved
            role_requests_table.update_item(
                Key={'request_id': request_id},
                UpdateExpression='SET #status = :status, approver_id = :approver_id, updated_at = :updated_at',
                ExpressionAttributeNames={'#status': 'status'},
                ExpressionAttributeValues={
                    ':status': 'approved',
                    ':approver_id': user.get('user_id'),
                    ':updated_at': now_kst.isoformat()
                }
            )

            # Schedule start and end
            scheduler.create_start_schedule(role_request)
            scheduler.create_end_schedule(role_request)

            # Send all notifications via notification_service
            requester_mattermost_id = get_mattermost_id_for_ticket(ticket)
            callback_url = os.environ.get("CALLBACK_URL", "")
            try:
                mattermost = MattermostClient()
                notify_approved(
                    mattermost=mattermost,
                    request_id=request_id,
                    requester_name=ticket.get('requester_name', ''),
                    requester_mattermost_id=requester_mattermost_id,
                    iam_user_name=ticket.get('iam_user_name', ''),
                    env=ticket.get('env', ''),
                    service=ticket.get('service', ''),
                    start_time_str=start_time.strftime('%Y-%m-%d %H:%M'),
                    end_time_str=end_time.strftime('%Y-%m-%d %H:%M'),
                    approver_name=user.get('name', ''),
                    permission_type=ticket.get('permission_type', 'read_update'),
                    target_services=ticket.get('target_services', ['all']),
                    callback_url=callback_url,
                    post_id=ticket.get('post_id'),
                    is_scheduled=True,
                    source="웹",
                )
            except Exception as e:
                print(f"[approve_ticket] Failed to send notifications: {e}")

            return response(200, {
                'request_id': request_id,
                'status': 'approved',
                'message': '승인 완료 - 시작 시간에 Role이 생성됩니다'
            })

        except Exception as e:
            print(f"[approve_ticket] Error creating schedules: {e}")
            return response(500, {'error': f'스케줄 생성 중 오류가 발생했습니다: {str(e)}'})


def reject_ticket(event: Dict[str, Any], request_id: str, body: Dict[str, Any]) -> Dict[str, Any]:
    """
    POST /api/tickets/{request_id}/reject
    Reject a pending ticket (Admin only)
    """
    # Check authentication
    user = get_current_user(event)
    if not user:
        return response(401, {'error': '인증이 필요합니다'})

    # Check admin permission
    if not user.get('is_admin', False):
        return response(403, {'error': '관리자 권한이 필요합니다'})

    rejection_reason = body.get('reason', '관리자에 의해 반려됨').strip()

    # Get ticket
    try:
        result = role_requests_table.get_item(Key={'request_id': request_id})
        ticket = result.get('Item')
    except Exception as e:
        print(f"[reject_ticket] Error fetching ticket: {e}")
        return response(500, {'error': '서버 오류가 발생했습니다'})

    if not ticket:
        return response(404, {'error': '티켓을 찾을 수 없습니다'})

    # Check status
    if ticket.get('status') != 'pending':
        return response(400, {'error': f'현재 상태({ticket.get("status")})에서는 반려할 수 없습니다'})

    # Update status
    now_kst = datetime.now(KST)
    try:
        role_requests_table.update_item(
            Key={'request_id': request_id},
            UpdateExpression='SET #status = :status, approver_id = :approver_id, rejection_reason = :rejection_reason, updated_at = :updated_at',
            ExpressionAttributeNames={'#status': 'status'},
            ExpressionAttributeValues={
                ':status': 'rejected',
                ':approver_id': user.get('user_id'),
                ':rejection_reason': rejection_reason,
                ':updated_at': now_kst.isoformat()
            }
        )
    except Exception as e:
        print(f"[reject_ticket] Error updating ticket: {e}")
        return response(500, {'error': '상태 변경 중 오류가 발생했습니다'})

    # Send notifications via notification_service
    requester_mattermost_id = get_mattermost_id_for_ticket(ticket)
    try:
        mattermost = MattermostClient()
        notify_rejected(
            mattermost=mattermost,
            request_id=request_id,
            requester_name=ticket.get('requester_name', ''),
            requester_mattermost_id=requester_mattermost_id,
            iam_user_name=ticket.get('iam_user_name', ''),
            env=ticket.get('env', ''),
            service=ticket.get('service', ''),
            rejecter_name=user.get('name', ''),
            rejection_reason=rejection_reason,
            post_id=ticket.get('post_id'),
            source="웹",
        )
    except Exception as e:
        print(f"[reject_ticket] Failed to send notifications: {e}")

    return response(200, {
        'request_id': request_id,
        'status': 'rejected',
        'message': '반려 처리되었습니다'
    })


def revoke_ticket(event: Dict[str, Any], request_id: str) -> Dict[str, Any]:
    """
    POST /api/tickets/{request_id}/revoke
    Revoke an active role (Admin only)
    """
    # Check authentication
    user = get_current_user(event)
    if not user:
        return response(401, {'error': '인증이 필요합니다'})

    # Check admin permission
    if not user.get('is_admin', False):
        return response(403, {'error': '관리자 권한이 필요합니다'})

    # Get ticket
    try:
        result = role_requests_table.get_item(Key={'request_id': request_id})
        ticket = result.get('Item')
    except Exception as e:
        print(f"[revoke_ticket] Error fetching ticket: {e}")
        return response(500, {'error': '서버 오류가 발생했습니다'})

    if not ticket:
        return response(404, {'error': '티켓을 찾을 수 없습니다'})

    # Check status
    if ticket.get('status') not in ['active', 'approved']:
        return response(400, {'error': f'현재 상태({ticket.get("status")})에서는 권한을 회수할 수 없습니다'})

    try:
        from services.role_manager import RoleManager
        from services.scheduler import Scheduler

        role_manager = RoleManager()
        scheduler = Scheduler()

        # Delete role if exists
        if ticket.get('role_arn') and ticket.get('policy_arn'):
            role_manager.delete_dynamic_role(ticket['role_arn'], ticket['policy_arn'])

        # Delete schedules
        scheduler.delete_schedule(f"role-create-{request_id}")
        scheduler.delete_schedule(f"role-delete-{request_id}")

        # Update status
        now_kst = datetime.now(KST)
        role_requests_table.update_item(
            Key={'request_id': request_id},
            UpdateExpression='SET #status = :status, approver_id = :approver_id, updated_at = :updated_at',
            ExpressionAttributeNames={'#status': 'status'},
            ExpressionAttributeValues={
                ':status': 'revoked',
                ':approver_id': user.get('user_id'),
                ':updated_at': now_kst.isoformat()
            }
        )

        # Send notifications via notification_service
        requester_mattermost_id = get_mattermost_id_for_ticket(ticket)
        try:
            mattermost = MattermostClient()
            notify_revoked(
                mattermost=mattermost,
                request_id=request_id,
                requester_name=ticket.get('requester_name', ''),
                requester_mattermost_id=requester_mattermost_id,
                iam_user_name=ticket.get('iam_user_name', ''),
                env=ticket.get('env', ''),
                service=ticket.get('service', ''),
                revoker_name=user.get('name', ''),
                post_id=ticket.get('post_id'),
                source="웹",
            )
        except Exception as e:
            print(f"[revoke_ticket] Failed to send notifications: {e}")

        return response(200, {
            'request_id': request_id,
            'status': 'revoked',
            'message': '권한이 회수되었습니다'
        })

    except Exception as e:
        print(f"[revoke_ticket] Error revoking: {e}")
        return response(500, {'error': f'권한 회수 중 오류가 발생했습니다: {str(e)}'})


# ========== Tag Config Endpoints ==========

def get_tags(event: Dict[str, Any], query_params: Dict[str, str]) -> Dict[str, Any]:
    """
    GET /api/tags?tag_type=env|service
    Get all tags of the specified type (admin only)
    """
    user = get_current_user(event)
    if not user:
        return response(401, {'error': '인증이 필요합니다'})
    if not user.get('is_admin'):
        return response(403, {'error': '관리자 권한이 필요합니다'})

    from services.tag_config_service import get_all_tags, seed_defaults, invalidate_cache

    tag_type = query_params.get('tag_type', '')
    if tag_type not in ('env', 'service'):
        return response(400, {'error': 'tag_type은 env 또는 service여야 합니다'})

    # Admin 페이지는 항상 최신 데이터 (Lambda 인스턴스 간 캐시 불일치 방지)
    invalidate_cache()
    items = get_all_tags(tag_type)

    # Auto-seed if empty (first access)
    if not items:
        try:
            seed_defaults()
            invalidate_cache()
            items = get_all_tags(tag_type)
        except Exception as e:
            print(f"[get_tags] seed_defaults error: {e}")

    return response(200, {'tags': items, 'count': len(items)})


def create_tag_endpoint(event: Dict[str, Any], body: Dict[str, Any]) -> Dict[str, Any]:
    """
    POST /api/tags
    Create a new tag (admin only)
    """
    user = get_current_user(event)
    if not user:
        return response(401, {'error': '인증이 필요합니다'})
    if not user.get('is_admin'):
        return response(403, {'error': '관리자 권한이 필요합니다'})

    from services.tag_config_service import create_tag

    tag_type = body.get('tag_type', '')
    tag_value = body.get('tag_value', '').strip()
    display_name = body.get('display_name', '').strip()
    sort_order = int(body.get('sort_order', 100))

    if tag_type not in ('env', 'service'):
        return response(400, {'error': 'tag_type은 env 또는 service여야 합니다'})
    if not tag_value:
        return response(400, {'error': 'tag_value는 필수 항목입니다'})

    try:
        item = create_tag(tag_type, tag_value, display_name, sort_order)
        return response(201, {'tag': item})
    except Exception as e:
        error_code = getattr(getattr(e, 'response', None), 'Error', {}).get('Code', '') if hasattr(e, 'response') else ''
        if 'ConditionalCheckFailed' in str(e) or error_code == 'ConditionalCheckFailedException':
            return response(409, {'error': f'이미 존재하는 태그입니다: {tag_value}'})
        print(f"[create_tag_endpoint] Error: {e}")
        return response(500, {'error': f'태그 생성 실패: {str(e)}'})


def update_tag_endpoint(event: Dict[str, Any], tag_type: str, tag_value: str, body: Dict[str, Any]) -> Dict[str, Any]:
    """
    PUT /api/tags/{tag_type}/{tag_value}
    Update an existing tag (admin only)
    """
    user = get_current_user(event)
    if not user:
        return response(401, {'error': '인증이 필요합니다'})
    if not user.get('is_admin'):
        return response(403, {'error': '관리자 권한이 필요합니다'})

    from services.tag_config_service import update_tag
    import urllib.parse
    tag_value = urllib.parse.unquote(tag_value)

    display_name = body.get('display_name')
    sort_order = body.get('sort_order')
    new_tag_value = body.get('new_tag_value', '').strip() or None
    if sort_order is not None:
        sort_order = int(sort_order)

    try:
        item = update_tag(tag_type, tag_value, display_name, sort_order, new_tag_value)
        return response(200, {'tag': item})
    except Exception as e:
        print(f"[update_tag_endpoint] Error: {e}")
        return response(500, {'error': f'태그 수정 실패: {str(e)}'})


def delete_tag_endpoint(event: Dict[str, Any], tag_type: str, tag_value: str) -> Dict[str, Any]:
    """
    DELETE /api/tags/{tag_type}/{tag_value}
    Delete a tag (admin only)
    """
    user = get_current_user(event)
    if not user:
        return response(401, {'error': '인증이 필요합니다'})
    if not user.get('is_admin'):
        return response(403, {'error': '관리자 권한이 필요합니다'})

    from services.tag_config_service import delete_tag
    import urllib.parse
    tag_value = urllib.parse.unquote(tag_value)

    try:
        delete_tag(tag_type, tag_value)
        return response(200, {'message': '태그가 삭제되었습니다'})
    except Exception as e:
        print(f"[delete_tag_endpoint] Error: {e}")
        return response(500, {'error': f'태그 삭제 실패: {str(e)}'})


def _query_by_status(table, status, limit=None):
    """Query GSI StatusCreatedIndex — 특정 status의 항목을 최신순으로 조회"""
    kwargs = {
        'IndexName': 'StatusCreatedIndex',
        'KeyConditionExpression': Key('status').eq(status),
        'ScanIndexForward': False,  # 최신순
    }
    if limit:
        kwargs['Limit'] = limit

    items = []
    result = table.query(**kwargs)
    items.extend(result.get('Items', []))
    if not limit:
        while 'LastEvaluatedKey' in result:
            kwargs['ExclusiveStartKey'] = result['LastEvaluatedKey']
            result = table.query(**kwargs)
            items.extend(result.get('Items', []))
    return items


def _query_count_by_status(table, status):
    """Query GSI StatusCreatedIndex — status별 카운트만 조회"""
    kwargs = {
        'IndexName': 'StatusCreatedIndex',
        'KeyConditionExpression': Key('status').eq(status),
        'Select': 'COUNT',
    }
    total = 0
    result = table.query(**kwargs)
    total += result.get('Count', 0)
    while 'LastEvaluatedKey' in result:
        kwargs['ExclusiveStartKey'] = result['LastEvaluatedKey']
        result = table.query(**kwargs)
        total += result.get('Count', 0)
    return total


def _scan_recent_activities(limit=5):
    """ActivityLogs에서 최근 N건 조회 — 최근 24시간만 FilterExpression으로 제한"""
    cutoff = (datetime.now(KST) - timedelta(hours=24)).isoformat()
    items = []
    kwargs = {
        'FilterExpression': Attr('event_time').gte(cutoff),
    }
    result = activity_logs_table.scan(**kwargs)
    items.extend(result.get('Items', []))
    while 'LastEvaluatedKey' in result:
        kwargs['ExclusiveStartKey'] = result['LastEvaluatedKey']
        result = activity_logs_table.scan(**kwargs)
        items.extend(result.get('Items', []))
    items.sort(key=lambda x: x.get('event_time', ''), reverse=True)
    return items[:limit]


def get_dashboard_summary(query_params: Dict[str, str]) -> Dict[str, Any]:
    """
    GET /api/dashboard-summary
    GSI Query 기반 — full scan 없이 필요한 데이터만 조회.
    """
    global _dashboard_cache

    now = time.time()
    if _dashboard_cache['data'] and (now - _dashboard_cache['timestamp']) < DASHBOARD_CACHE_TTL:
        print("[get_dashboard_summary] Returning cached data")
        return response(200, _dashboard_cache['data'])

    print("[get_dashboard_summary] Building fresh data via GSI queries")
    start = time.time()

    try:
        # RoleRequests — GSI StatusCreatedIndex로 조회
        active_count = _query_count_by_status(role_requests_table, 'active')
        pending_count = _query_count_by_status(role_requests_table, 'pending')
        pending_tickets = _query_by_status(role_requests_table, 'pending', limit=5)

        # 최근 티켓 5건: 여러 status에서 최신순으로 가져와서 merge
        recent_tickets = []
        for s in ['pending', 'approved', 'active', 'expired', 'rejected', 'revoked', 'error']:
            recent_tickets.extend(_query_by_status(role_requests_table, s, limit=5))
        recent_tickets.sort(key=lambda x: x.get('created_at', ''), reverse=True)
        recent_tickets = recent_tickets[:5]

        # WorkRequests — GSI StatusCreatedIndex로 조회
        pending_wr_count = _query_count_by_status(work_requests_table, 'pending')
        in_progress_wr_count = _query_count_by_status(work_requests_table, 'in_progress')
        total_wr_count = 0
        for s in ['pending', 'in_progress', 'completed', 'cancelled']:
            total_wr_count += _query_count_by_status(work_requests_table, s)

        recent_wr = []
        for s in ['pending', 'in_progress', 'completed', 'cancelled']:
            recent_wr.extend(_query_by_status(work_requests_table, s, limit=5))
        recent_wr.sort(key=lambda x: x.get('created_at', ''), reverse=True)
        recent_wr = recent_wr[:5]

        # Activities — 캐시 활용, 없으면 최근 24시간만 scan
        activities = []
        if _activities_cache['items'] is not None and (now - _activities_cache['timestamp']) < ACTIVITIES_CACHE_TTL:
            activities = _activities_cache['items'][:5]
        else:
            activities = _scan_recent_activities(limit=5)
            _activities_cache['items'] = activities
            _activities_cache['timestamp'] = now

        data = {
            'stats': {
                'activeTickets': active_count,
                'pendingTickets': pending_count,
                'totalWorkRequests': total_wr_count,
                'pendingWorkRequests': pending_wr_count,
                'inProgressWorkRequests': in_progress_wr_count,
            },
            'recentTickets': recent_tickets,
            'pendingTickets': pending_tickets,
            'recentWorkRequests': recent_wr,
            'recentActivities': activities,
        }

        _dashboard_cache['data'] = data
        _dashboard_cache['timestamp'] = time.time()
        print(f"[get_dashboard_summary] Done in {time.time() - start:.2f}s")
        return response(200, data)

    except Exception as e:
        print(f"[get_dashboard_summary] Error: {e}")
        if _dashboard_cache['data']:
            return response(200, _dashboard_cache['data'])
        return response(500, {'error': f'대시보드 데이터 조회 실패: {str(e)}'})


def response(status_code: int, body: Dict[str, Any]) -> Dict[str, Any]:
    """Create API Gateway response with CORS headers"""
    return {
        'statusCode': status_code,
        'headers': {
            'Content-Type': 'application/json',
            'Access-Control-Allow-Origin': '*',
            'Access-Control-Allow-Headers': 'Content-Type,Authorization,X-API-Key',
            'Access-Control-Allow-Methods': 'GET,POST,PUT,PATCH,DELETE,OPTIONS'
        },
        'body': json.dumps(body, default=str)
    }
