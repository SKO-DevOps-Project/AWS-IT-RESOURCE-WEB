import React, { useEffect, useState } from 'react';
import { getMyRequests, Ticket } from '../api';
import { useAuth } from '../contexts/AuthContext';
import './Pages.css';

const statusColors: Record<string, string> = {
  pending: '#f59e0b',
  approved: '#3b82f6',
  active: '#10b981',
  expired: '#6b7280',
  revoked: '#ef4444',
  rejected: '#ef4444',
  error: '#ef4444',
};

const statusLabels: Record<string, string> = {
  pending: '승인대기',
  approved: '승인됨',
  active: '활성',
  expired: '만료됨',
  revoked: '회수됨',
  rejected: '반려됨',
  error: '오류',
};

const permissionLabels: Record<string, string> = {
  read_only: '조회',
  read_update: '조회+수정',
  read_update_create: '조회+수정+생성',
  full: '전체',
};

type TabKey = 'mac' | 'cmd' | 'powershell' | 'console';

const buildMacScript = (roleArn: string, iamUser: string): string =>
  `# 1. assume-role 실행
CREDS=$(aws sts assume-role \\
  --role-arn ${roleArn} \\
  --role-session-name ${iamUser}-session \\
  --query 'Credentials' --output json)

# 2. 환경변수 설정
export AWS_ACCESS_KEY_ID=$(echo $CREDS | jq -r '.AccessKeyId')
export AWS_SECRET_ACCESS_KEY=$(echo $CREDS | jq -r '.SecretAccessKey')
export AWS_SESSION_TOKEN=$(echo $CREDS | jq -r '.SessionToken')

# 3. 확인
aws sts get-caller-identity`;

const buildPowerShellScript = (roleArn: string, iamUser: string): string =>
  `$creds = (aws sts assume-role \`
  --role-arn ${roleArn} \`
  --role-session-name ${iamUser}-session \`
  --query "Credentials" --output json) | ConvertFrom-Json

$env:AWS_ACCESS_KEY_ID = $creds.AccessKeyId
$env:AWS_SECRET_ACCESS_KEY = $creds.SecretAccessKey
$env:AWS_SESSION_TOKEN = $creds.SessionToken

aws sts get-caller-identity`;

const buildCmdScript = (roleArn: string, iamUser: string): string =>
  `aws sts assume-role --role-arn ${roleArn} --role-session-name ${iamUser}-session --query "Credentials" --output json

:: 위 결과에서 값을 복사 후:
set AWS_ACCESS_KEY_ID=<AccessKeyId>
set AWS_SECRET_ACCESS_KEY=<SecretAccessKey>
set AWS_SESSION_TOKEN=<SessionToken>

aws sts get-caller-identity`;

const buildConsoleGuide = (roleArn: string): string => {
  const roleName = roleArn.includes('/') ? roleArn.split('/').pop() : roleArn;
  return `1. AWS Console 우측 상단 → Switch Role
2. Account: 680877507363
3. Role: ${roleName}`;
};

const MyRequests: React.FC = () => {
  const { user } = useAuth();
  const [tickets, setTickets] = useState<Ticket[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [openId, setOpenId] = useState<string | null>(null);
  const [activeTabs, setActiveTabs] = useState<Record<string, TabKey>>({});
  const [copiedId, setCopiedId] = useState<string | null>(null);

  useEffect(() => {
    const fetchData = async () => {
      if (!user?.iam_user_name) {
        setLoading(false);
        return;
      }
      try {
        const data = await getMyRequests(user.iam_user_name);
        setTickets(data.tickets || []);
      } catch (err) {
        console.error('Failed to fetch my requests:', err);
        setError('요청 목록을 불러올 수 없습니다.');
      } finally {
        setLoading(false);
      }
    };
    fetchData();
  }, [user]);

  const toggleAccordion = (id: string) => {
    setOpenId(openId === id ? null : id);
  };

  const setTab = (id: string, tab: TabKey) => {
    setActiveTabs(prev => ({ ...prev, [id]: tab }));
  };

  const getTab = (id: string): TabKey => activeTabs[id] || 'mac';

  const handleCopy = async (text: string, id: string) => {
    try {
      await navigator.clipboard.writeText(text);
      setCopiedId(id);
      setTimeout(() => setCopiedId(null), 2000);
    } catch {
      // fallback
    }
  };

  const getCodeForTab = (ticket: Ticket, tab: TabKey): string => {
    const arn = ticket.role_arn || '';
    const iam = ticket.iam_user_name || '';
    switch (tab) {
      case 'mac': return buildMacScript(arn, iam);
      case 'powershell': return buildPowerShellScript(arn, iam);
      case 'cmd': return buildCmdScript(arn, iam);
      case 'console': return buildConsoleGuide(arn);
    }
  };

  const formatDate = (dateStr: string) => {
    if (!dateStr) return '-';
    return dateStr.replace('T', ' ').slice(0, 16);
  };

  if (loading) {
    return (
      <div className="page">
        <div className="page-header">
          <h2>나의 권한 요청</h2>
        </div>
        <div className="loading-container">
          <div className="loading-spinner" />
          <p>로딩 중...</p>
        </div>
      </div>
    );
  }

  if (!user?.iam_user_name) {
    return (
      <div className="page">
        <div className="page-header">
          <h2>나의 권한 요청</h2>
        </div>
        <div className="empty-state">
          <p>IAM 사용자 정보가 설정되지 않았습니다.</p>
        </div>
      </div>
    );
  }

  return (
    <div className="page">
      <div className="page-header">
        <h2>나의 권한 요청</h2>
        <p className="page-description">내가 요청한 AWS Role 권한 내역입니다.</p>
      </div>

      {error && <div className="toast toast-error" style={{ marginBottom: 16 }}>{error}</div>}

      {tickets.length === 0 ? (
        <div className="empty-state">
          <p>요청 내역이 없습니다.</p>
        </div>
      ) : (
        <div className="my-requests-list">
          {tickets.map(ticket => {
            const isOpen = openId === ticket.request_id;
            const isActive = ticket.status === 'active';
            const tab = getTab(ticket.request_id);
            const code = isActive ? getCodeForTab(ticket, tab) : '';

            return (
              <div key={ticket.request_id} className={`accordion-card ${isOpen ? 'open' : ''}`}>
                <div className="accordion-header" onClick={() => toggleAccordion(ticket.request_id)}>
                  <div className="accordion-summary">
                    <span
                      className="status-badge"
                      style={{ backgroundColor: statusColors[ticket.status] || '#6b7280' }}
                    >
                      {statusLabels[ticket.status] || ticket.status}
                    </span>
                    <span className="accordion-env-service">
                      {ticket.env} / {ticket.service}
                    </span>
                    <span className="accordion-permission">
                      {permissionLabels[ticket.permission_type] || ticket.permission_type}
                    </span>
                  </div>
                  <div className="accordion-meta">
                    <span className="accordion-date">
                      {formatDate(ticket.start_time)} ~ {formatDate(ticket.end_time)}
                    </span>
                    <span className={`accordion-arrow ${isOpen ? 'open' : ''}`}>&#9662;</span>
                  </div>
                </div>

                {isOpen && (
                  <div className="accordion-body">
                    <div className="accordion-detail-grid">
                      <div className="accordion-detail-item">
                        <span className="accordion-detail-label">요청자</span>
                        <span>{ticket.requester_name}</span>
                      </div>
                      <div className="accordion-detail-item">
                        <span className="accordion-detail-label">IAM 사용자</span>
                        <span>{ticket.iam_user_name}</span>
                      </div>
                      <div className="accordion-detail-item">
                        <span className="accordion-detail-label">대상 서비스</span>
                        <span>{(ticket.target_services || []).join(', ')}</span>
                      </div>
                      <div className="accordion-detail-item">
                        <span className="accordion-detail-label">목적</span>
                        <span>{ticket.purpose}</span>
                      </div>
                      {ticket.role_arn && (
                        <div className="accordion-detail-item">
                          <span className="accordion-detail-label">Role ARN</span>
                          <span className="accordion-arn">{ticket.role_arn}</span>
                        </div>
                      )}
                    </div>

                    {isActive && ticket.role_arn && (
                      <div className="usage-section">
                        <h4 className="usage-title">역할 사용 방법</h4>
                        <div className="usage-tabs">
                          {([
                            ['mac', 'Mac/Linux'],
                            ['cmd', 'Windows (CMD)'],
                            ['powershell', 'PowerShell'],
                            ['console', 'AWS Console'],
                          ] as [TabKey, string][]).map(([key, label]) => (
                            <button
                              key={key}
                              className={`usage-tab ${tab === key ? 'active' : ''}`}
                              onClick={() => setTab(ticket.request_id, key)}
                            >
                              {label}
                            </button>
                          ))}
                        </div>
                        <div className="code-block-wrapper">
                          <pre className="code-block">{code}</pre>
                          <button
                            className="copy-btn"
                            onClick={() => handleCopy(code, ticket.request_id)}
                          >
                            {copiedId === ticket.request_id ? '복사됨!' : '복사'}
                          </button>
                        </div>
                      </div>
                    )}
                  </div>
                )}
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
};

export default MyRequests;
