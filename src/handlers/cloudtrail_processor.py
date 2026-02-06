"""
CloudTrail Log Processor Lambda Handler

S3에 저장된 CloudTrail 로그를 파싱하여 dynamic-role 관련 이벤트만
ActivityLogs DynamoDB 테이블에 저장합니다.
"""

import json
import gzip
import boto3
import os
import re
import uuid
from datetime import datetime, timedelta, timezone

# Korea Standard Time (UTC+9)
KST = timezone(timedelta(hours=9))
from typing import Optional, List, Dict, Any
from urllib.parse import unquote_plus


# DynamoDB 테이블 이름
ACTIVITY_LOGS_TABLE = os.environ.get('ACTIVITY_LOGS_TABLE', 'ActivityLogs')

# dynamic-role 패턴
DYNAMIC_ROLE_PATTERN = re.compile(r'dynamic-role-[\w-]+')

# AWS 클라이언트
s3_client = boto3.client('s3')
dynamodb = boto3.resource('dynamodb')
activity_logs_table = dynamodb.Table(ACTIVITY_LOGS_TABLE)


def handler(event: Dict[str, Any], context: Any) -> Dict[str, Any]:
    """
    S3 Event로 트리거되는 Lambda 핸들러

    Args:
        event: S3 이벤트
        context: Lambda 컨텍스트

    Returns:
        처리 결과
    """
    processed_count = 0
    error_count = 0

    for record in event.get('Records', []):
        try:
            # S3 버킷과 키 추출
            bucket = record['s3']['bucket']['name']
            key = unquote_plus(record['s3']['object']['key'])

            print(f"Processing: s3://{bucket}/{key}")

            # CloudTrail 로그 파일이 아니면 스킵
            if not key.endswith('.json.gz'):
                print(f"Skipping non-CloudTrail file: {key}")
                continue

            # S3에서 파일 다운로드 및 파싱
            logs = download_and_parse_cloudtrail(bucket, key)

            # dynamic-role 관련 이벤트 필터링 및 저장
            for log in logs:
                activity_log = parse_cloudtrail_record(log)
                if activity_log:
                    save_activity_log(activity_log)
                    processed_count += 1

        except Exception as e:
            print(f"Error processing record: {e}")
            error_count += 1

    result = {
        'statusCode': 200,
        'body': json.dumps({
            'processed': processed_count,
            'errors': error_count
        })
    }

    print(f"Completed: {processed_count} logs processed, {error_count} errors")
    return result


def download_and_parse_cloudtrail(bucket: str, key: str) -> List[Dict]:
    """
    S3에서 CloudTrail 로그 파일을 다운로드하고 파싱

    Args:
        bucket: S3 버킷 이름
        key: S3 객체 키

    Returns:
        CloudTrail 레코드 리스트
    """
    # S3에서 파일 다운로드
    response = s3_client.get_object(Bucket=bucket, Key=key)

    # gzip 해제
    compressed_data = response['Body'].read()
    decompressed_data = gzip.decompress(compressed_data)

    # JSON 파싱
    cloudtrail_data = json.loads(decompressed_data.decode('utf-8'))

    return cloudtrail_data.get('Records', [])


def parse_cloudtrail_record(record: Dict) -> Optional[Dict]:
    """
    CloudTrail 레코드에서 필요한 정보 추출

    Args:
        record: CloudTrail 레코드

    Returns:
        ActivityLog 딕셔너리 또는 None (dynamic-role이 아닌 경우)
    """
    user_identity = record.get('userIdentity', {})

    # AssumedRole 타입만 처리
    if user_identity.get('type') != 'AssumedRole':
        return None

    # ARN에서 role 정보 추출
    arn = user_identity.get('arn', '')

    # dynamic-role 패턴 확인
    if 'dynamic-role-' not in arn:
        return None

    # ARN 파싱: arn:aws:sts::ACCOUNT:assumed-role/ROLE_NAME/SESSION_NAME
    arn_parts = arn.split('/')
    if len(arn_parts) < 3:
        return None

    role_name = arn_parts[1]  # dynamic-role-xxx
    session_name = arn_parts[2]  # hchang-session

    # session_name에서 사용자명 추출 (예: hchang-session -> hchang)
    iam_user_name = extract_user_from_session(session_name)

    # role_arn 구성
    account_id = user_identity.get('accountId', '')
    role_arn = f"arn:aws:iam::{account_id}:role/{role_name}"

    # 리소스 정보 추출
    resources = extract_resources(record)

    # TTL 계산 (90일 후)
    ttl_timestamp = int((datetime.now(KST) + timedelta(days=90)).timestamp())

    # ActivityLog 생성
    activity_log = {
        'log_id': str(uuid.uuid4()),
        'role_name': role_name,
        'role_arn': role_arn,
        'session_name': session_name,
        'iam_user_name': iam_user_name,
        'event_time': record.get('eventTime', ''),
        'event_name': record.get('eventName', ''),
        'event_source': record.get('eventSource', ''),
        'aws_region': record.get('awsRegion', ''),
        'source_ip': record.get('sourceIPAddress', ''),
        'user_agent': record.get('userAgent', ''),
        'error_code': record.get('errorCode'),
        'error_message': record.get('errorMessage'),
        'resources': resources,
        'event_id': record.get('eventID', ''),
        'raw_event': json.dumps(record),
        'ttl_timestamp': ttl_timestamp
    }

    return activity_log


def extract_user_from_session(session_name: str) -> str:
    """
    세션 이름에서 사용자명 추출

    예시:
    - hchang-session -> hchang
    - hchang -> hchang
    - user123-prod-session -> user123

    Args:
        session_name: 세션 이름

    Returns:
        추출된 사용자명
    """
    # -session 접미사 제거
    if session_name.endswith('-session'):
        return session_name[:-8]

    # 첫 번째 - 이전 부분 반환 (없으면 전체)
    parts = session_name.split('-')
    return parts[0] if parts else session_name


def extract_resources(record: Dict) -> List[Dict]:
    """
    CloudTrail 레코드에서 리소스 정보 추출

    Args:
        record: CloudTrail 레코드

    Returns:
        리소스 정보 리스트
    """
    resources = []

    for resource in record.get('resources', []):
        resources.append({
            'arn': resource.get('ARN', ''),
            'type': resource.get('type', ''),
            'account_id': resource.get('accountId', '')
        })

    return resources


def save_activity_log(activity_log: Dict) -> None:
    """
    ActivityLog를 DynamoDB에 저장

    Args:
        activity_log: 저장할 ActivityLog
    """
    # None 값 제거 (DynamoDB는 None을 허용하지 않음)
    item = {k: v for k, v in activity_log.items() if v is not None}

    # 빈 문자열도 제거
    item = {k: v for k, v in item.items() if v != ''}

    # 빈 리스트는 유지
    if 'resources' in activity_log and not activity_log['resources']:
        item['resources'] = []

    activity_logs_table.put_item(Item=item)

    print(f"Saved: {activity_log['event_name']} by {activity_log['iam_user_name']} at {activity_log['event_time']}")
