#!/bin/bash

# AWS Role Request System 배포 스크립트

# Mattermost 설정
MATTERMOST_BOT_TOKEN="n3k3bi6wg7dydytqp5cu1ftt8e"
MATTERMOST_URL="https://mattermost.skons.net"
REQUEST_CHANNEL_WEBHOOK="https://mattermost.skons.net/hooks/b49cagrr4f8qjbjqa57x664hme"
APPROVAL_CHANNEL_WEBHOOK="https://mattermost.skons.net/hooks/4t5ejuiari8dm8ntxcbg17jtqc"
APPROVAL_CHANNEL_ID="butcpzxmxtrope36m3urgk8m7r"
REQUEST_CHANNEL_ID="su1gjq6usbdixcbn4bdepm8o1r"

# Admin 및 보안 설정
ADMIN_USER_IDS="tyns8anuhbymtgjwytcg4inmqy,fjfmg5rmobdupyenr78tmjjsco"
COMPANY_IP_RANGE="0.0.0.0/0"

echo "=== AWS Role Request System 배포 ==="
echo ""

# SAM 빌드
echo "1. SAM 빌드 중..."
sam build

if [ $? -ne 0 ]; then
    echo "❌ SAM 빌드 실패"
    exit 1
fi

echo "✅ SAM 빌드 완료"
echo ""

# SAM 배포
echo "2. SAM 배포 중..."
sam deploy \
    --parameter-overrides \
        MattermostUrl="${MATTERMOST_URL}" \
        MattermostBotToken="${MATTERMOST_BOT_TOKEN}" \
        RequestChannelWebhook="${REQUEST_CHANNEL_WEBHOOK}" \
        ApprovalChannelWebhook="${APPROVAL_CHANNEL_WEBHOOK}" \
        ApprovalChannelId="${APPROVAL_CHANNEL_ID}" \
        AdminUserIds="${ADMIN_USER_IDS}" \
        CompanyIpRange="${COMPANY_IP_RANGE}" \
    --no-confirm-changeset

if [ $? -ne 0 ]; then
    echo "❌ SAM 배포 실패"
    exit 1
fi

echo ""
echo "✅ 배포 완료!"
echo ""
echo "=== 다음 단계 ==="
echo "1. AWS Console에서 API Gateway URL 확인"
echo "2. Mattermost에서 Slash Command 설정:"
echo "   - /request-role -> {API_URL}/slash"
echo "   - /master-request-role -> {API_URL}/slash"
echo ""
