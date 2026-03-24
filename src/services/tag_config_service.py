"""
Tag Configuration Service
DynamoDB-backed tag management for Environment and Service values
with in-memory caching and hardcoded fallback.
"""
import os
import time
import boto3
from datetime import datetime, timezone, timedelta
from typing import List, Dict, Any, Optional

# Korea Standard Time (UTC+9)
KST = timezone(timedelta(hours=9))

# Cache TTL: 10 seconds (Lambda 인스턴스 간 캐시 불일치 최소화)
_CACHE_TTL = 10
_cache: Dict[str, Any] = {}
_cache_timestamps: Dict[str, float] = {}

# Fallback values (from original hardcoded constants)
_FALLBACK_ENVS = ["prod", "test", "infra", "staging", "dev"]

_FALLBACK_SERVICES = [
    "aihub", "safety", "infra", "biz_drive", "alarm",
    "unit-mgnt", "software-updater", "sms-sender", "ai-nams",
    "fleet-mgnt", "bp-eval", "form-system", "sko-sso-auth",
    "sko-sftp", "asset-mgmt", "ocean", "security365", "kca",
    "core"
]

_FALLBACK_SERVICE_DISPLAY_NAMES = {
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
    "kca": "무선국관리시스템",
    "core": "Core시스템",
}


def _get_table():
    """Get DynamoDB TagConfig table"""
    dynamodb = boto3.resource('dynamodb')
    table_name = os.environ.get('TAG_CONFIG_TABLE', 'TagConfig')
    return dynamodb.Table(table_name)


def _get_cached(key: str) -> Optional[Any]:
    """Get value from cache if not expired"""
    if key in _cache and key in _cache_timestamps:
        if time.time() - _cache_timestamps[key] < _CACHE_TTL:
            return _cache[key]
    return None


def _set_cached(key: str, value: Any):
    """Set value in cache"""
    _cache[key] = value
    _cache_timestamps[key] = time.time()


def invalidate_cache():
    """Clear all cached values (call after writes)"""
    _cache.clear()
    _cache_timestamps.clear()


def get_all_tags(tag_type: str) -> List[Dict[str, Any]]:
    """
    Get all tags of a given type from DynamoDB.
    Returns list sorted by sort_order.
    """
    cache_key = f"all_tags_{tag_type}"
    cached = _get_cached(cache_key)
    if cached is not None:
        return cached

    try:
        table = _get_table()
        result = table.query(
            KeyConditionExpression=boto3.dynamodb.conditions.Key('tag_type').eq(tag_type)
        )
        items = result.get('Items', [])
        items.sort(key=lambda x: int(x.get('sort_order', 999)))
        _set_cached(cache_key, items)
        return items
    except Exception as e:
        print(f"[tag_config_service] Error fetching tags for {tag_type}: {e}")
        return []


def get_valid_envs() -> List[str]:
    """Get valid environment values. Falls back to hardcoded if DynamoDB is empty."""
    cache_key = "valid_envs"
    cached = _get_cached(cache_key)
    if cached is not None:
        return cached

    try:
        items = get_all_tags("env")
        if items:
            result = [item['tag_value'] for item in items]
            _set_cached(cache_key, result)
            return result
    except Exception as e:
        print(f"[tag_config_service] Error in get_valid_envs: {e}")

    return _FALLBACK_ENVS


def get_valid_services() -> List[str]:
    """Get valid service values. Falls back to hardcoded if DynamoDB is empty."""
    cache_key = "valid_services"
    cached = _get_cached(cache_key)
    if cached is not None:
        return cached

    try:
        items = get_all_tags("service")
        if items:
            result = [item['tag_value'] for item in items]
            _set_cached(cache_key, result)
            return result
    except Exception as e:
        print(f"[tag_config_service] Error in get_valid_services: {e}")

    return _FALLBACK_SERVICES


def get_service_display_names() -> Dict[str, str]:
    """Get service display names mapping. Falls back to hardcoded if DynamoDB is empty."""
    cache_key = "service_display_names"
    cached = _get_cached(cache_key)
    if cached is not None:
        return cached

    try:
        items = get_all_tags("service")
        if items:
            result = {}
            for item in items:
                display = item.get('display_name', '')
                if display:
                    result[item['tag_value']] = display
            _set_cached(cache_key, result)
            return result
    except Exception as e:
        print(f"[tag_config_service] Error in get_service_display_names: {e}")

    return _FALLBACK_SERVICE_DISPLAY_NAMES


def create_tag(tag_type: str, tag_value: str, display_name: str = "", sort_order: int = 100) -> Dict[str, Any]:
    """Create a new tag config entry"""
    now_kst = datetime.now(KST).isoformat()
    item = {
        'tag_type': tag_type,
        'tag_value': tag_value,
        'display_name': display_name,
        'sort_order': sort_order,
        'created_at': now_kst,
    }

    table = _get_table()
    table.put_item(
        Item=item,
        ConditionExpression='attribute_not_exists(tag_type) AND attribute_not_exists(tag_value)',
    )
    invalidate_cache()
    return item


def update_tag(tag_type: str, tag_value: str, display_name: str = None, sort_order: int = None, new_tag_value: str = None) -> Dict[str, Any]:
    """Update an existing tag config entry. If new_tag_value is given, delete old and create new (key change)."""
    table = _get_table()

    # If tag_value itself is changing, delete old + create new
    if new_tag_value and new_tag_value != tag_value:
        # Get existing item
        result = table.get_item(Key={'tag_type': tag_type, 'tag_value': tag_value})
        old_item = result.get('Item', {})

        new_item = {
            'tag_type': tag_type,
            'tag_value': new_tag_value,
            'display_name': display_name if display_name is not None else old_item.get('display_name', ''),
            'sort_order': sort_order if sort_order is not None else old_item.get('sort_order', 100),
            'created_at': old_item.get('created_at', datetime.now(KST).isoformat()),
        }

        table.delete_item(Key={'tag_type': tag_type, 'tag_value': tag_value})
        table.put_item(Item=new_item)
        invalidate_cache()
        return new_item

    # Otherwise, in-place update
    update_parts = []
    expression_values = {}
    expression_names = {}

    if display_name is not None:
        update_parts.append('#dn = :dn')
        expression_values[':dn'] = display_name
        expression_names['#dn'] = 'display_name'

    if sort_order is not None:
        update_parts.append('sort_order = :so')
        expression_values[':so'] = sort_order

    if not update_parts:
        return {}

    kwargs = {
        'Key': {'tag_type': tag_type, 'tag_value': tag_value},
        'UpdateExpression': 'SET ' + ', '.join(update_parts),
        'ExpressionAttributeValues': expression_values,
        'ReturnValues': 'ALL_NEW',
    }
    if expression_names:
        kwargs['ExpressionAttributeNames'] = expression_names

    result = table.update_item(**kwargs)
    invalidate_cache()
    return result.get('Attributes', {})


def delete_tag(tag_type: str, tag_value: str):
    """Delete a tag config entry"""
    table = _get_table()
    table.delete_item(Key={'tag_type': tag_type, 'tag_value': tag_value})
    invalidate_cache()


def seed_defaults():
    """Seed DynamoDB with default hardcoded values (run once on first access)"""
    table = _get_table()

    # Seed environments
    for i, env in enumerate(_FALLBACK_ENVS):
        now_kst = datetime.now(KST).isoformat()
        try:
            table.put_item(
                Item={
                    'tag_type': 'env',
                    'tag_value': env,
                    'display_name': env,
                    'sort_order': (i + 1) * 10,
                    'created_at': now_kst,
                },
                ConditionExpression='attribute_not_exists(tag_type)',
            )
        except Exception:
            # Item already exists, skip
            pass

    # Seed services
    for i, svc in enumerate(_FALLBACK_SERVICES):
        now_kst = datetime.now(KST).isoformat()
        try:
            table.put_item(
                Item={
                    'tag_type': 'service',
                    'tag_value': svc,
                    'display_name': _FALLBACK_SERVICE_DISPLAY_NAMES.get(svc, svc),
                    'sort_order': (i + 1) * 10,
                    'created_at': now_kst,
                },
                ConditionExpression='attribute_not_exists(tag_type)',
            )
        except Exception:
            # Item already exists, skip
            pass

    invalidate_cache()
