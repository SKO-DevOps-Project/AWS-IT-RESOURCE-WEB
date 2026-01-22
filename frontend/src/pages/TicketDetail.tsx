import React, { useEffect, useState } from 'react';
import { useParams, Link } from 'react-router-dom';
import { getTicketDetail, getWorkRequests, updateTicketWorkRequest, Ticket, Activity, WorkRequest } from '../api';
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
  read_only: '조회만',
  read_update: '조회+수정',
  read_update_create: '조회+수정+생성',
  full: '전체(삭제포함)',
};

const TicketDetail: React.FC = () => {
  const { requestId } = useParams<{ requestId: string }>();
  const { user } = useAuth();
  const [ticket, setTicket] = useState<Ticket | null>(null);
  const [activities, setActivities] = useState<Activity[]>([]);
  const [loading, setLoading] = useState(true);
  const [selectedActivity, setSelectedActivity] = useState<Activity | null>(null);
  const [workRequests, setWorkRequests] = useState<WorkRequest[]>([]);
  const [linkedWorkRequest, setLinkedWorkRequest] = useState<WorkRequest | null>(null);
  const [selectedWorkRequestId, setSelectedWorkRequestId] = useState<string>('');
  const [saving, setSaving] = useState(false);

  useEffect(() => {
    if (requestId) {
      loadTicketDetail();
      loadWorkRequests();
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [requestId]);

  const loadTicketDetail = async () => {
    setLoading(true);
    try {
      const data = await getTicketDetail(requestId!);
      setTicket(data.ticket);
      setActivities(data.activities || []);
      setLinkedWorkRequest(data.work_request || null);
      setSelectedWorkRequestId(data.ticket?.work_request_id || '');
    } catch (error) {
      console.error('Failed to load ticket detail:', error);
    } finally {
      setLoading(false);
    }
  };

  const loadWorkRequests = async () => {
    try {
      const data = await getWorkRequests({ limit: 100 });
      setWorkRequests(data.work_requests || []);
    } catch (error) {
      console.error('Failed to load work requests:', error);
    }
  };

  const handleLinkWorkRequest = async () => {
    if (!requestId) return;
    setSaving(true);
    try {
      await updateTicketWorkRequest(requestId, selectedWorkRequestId || null);
      await loadTicketDetail();
    } catch (error) {
      console.error('Failed to link work request:', error);
    } finally {
      setSaving(false);
    }
  };

  const formatDateTime = (isoString: string) => {
    const date = new Date(isoString);
    return date.toLocaleString('ko-KR', {
      timeZone: 'Asia/Seoul',
      year: 'numeric',
      month: '2-digit',
      day: '2-digit',
      hour: '2-digit',
      minute: '2-digit',
      second: '2-digit',
    });
  };

  const getServiceFromSource = (eventSource: string) => {
    return eventSource.split('.')[0].toUpperCase();
  };

  if (loading) {
    return <div className="page"><div className="loading">로딩 중...</div></div>;
  }

  if (!ticket) {
    return <div className="page"><div className="empty-state">티켓을 찾을 수 없습니다.</div></div>;
  }

  return (
    <div className="page">
      <div className="page-header">
        <Link to="/" className="back-link">← 목록으로</Link>
        <h2>티켓 상세</h2>
      </div>

      <div className="detail-card">
        <div className="detail-header">
          <span
            className="status-badge large"
            style={{ backgroundColor: statusColors[ticket.status] || '#6b7280' }}
          >
            {statusLabels[ticket.status] || ticket.status}
          </span>
          <span className="ticket-id">ID: {ticket.request_id}</span>
        </div>

        <div className="detail-grid">
          <div className="detail-item">
            <label>요청자</label>
            <span>{ticket.requester_name}</span>
          </div>
          <div className="detail-item">
            <label>IAM User</label>
            <span>{ticket.iam_user_name}</span>
          </div>
          <div className="detail-item">
            <label>Environment</label>
            <span>{ticket.env}</span>
          </div>
          <div className="detail-item">
            <label>Service</label>
            <span>{ticket.service}</span>
          </div>
          <div className="detail-item">
            <label>권한 유형</label>
            <span>{permissionLabels[ticket.permission_type] || ticket.permission_type}</span>
          </div>
          <div className="detail-item">
            <label>대상 서비스</label>
            <span>{ticket.target_services?.join(', ') || 'all'}</span>
          </div>
          <div className="detail-item">
            <label>시작 시간</label>
            <span>{formatDateTime(ticket.start_time)}</span>
          </div>
          <div className="detail-item">
            <label>종료 시간</label>
            <span>{formatDateTime(ticket.end_time)}</span>
          </div>
          <div className="detail-item full-width">
            <label>목적</label>
            <span>{ticket.purpose}</span>
          </div>
          {ticket.role_arn && (
            <div className="detail-item full-width">
              <label>Role ARN</label>
              <code>{ticket.role_arn}</code>
            </div>
          )}
        </div>
      </div>

      {/* 연관 업무 요청 섹션 */}
      <div className="detail-card">
        <div className="section-header">
          <h3>연관 업무 요청</h3>
        </div>
        {linkedWorkRequest ? (
          <div className="linked-work-request-detail">
            <div className="linked-work-request-info">
              <div className="linked-work-request-row">
                <div className="linked-work-request-item">
                  <label>서비스</label>
                  <span className="service-badge">{linkedWorkRequest.service_display_name}</span>
                </div>
                <div className="linked-work-request-item">
                  <label>요청자</label>
                  <span>{linkedWorkRequest.requester_name}</span>
                </div>
                <div className="linked-work-request-item">
                  <label>작업 기간</label>
                  <span>{linkedWorkRequest.start_date} ~ {linkedWorkRequest.end_date}</span>
                </div>
                <div className="linked-work-request-item">
                  <label>요청일</label>
                  <span>{formatDateTime(linkedWorkRequest.created_at)}</span>
                </div>
              </div>
              <div className="linked-work-request-row">
                <div className="linked-work-request-item full-width">
                  <label>작업 내용</label>
                  <span>{linkedWorkRequest.description}</span>
                </div>
              </div>
            </div>
            {user?.is_admin && (
              <div className="link-actions-row">
                <select
                  value={selectedWorkRequestId}
                  onChange={(e) => setSelectedWorkRequestId(e.target.value)}
                  className="filter-select"
                >
                  <option value="">연결 해제</option>
                  {workRequests.map((wr) => (
                    <option key={wr.request_id} value={wr.request_id}>
                      [{wr.service_display_name}] {wr.description.substring(0, 30)}...
                    </option>
                  ))}
                </select>
                <button
                  onClick={handleLinkWorkRequest}
                  disabled={saving}
                  className="btn btn-primary btn-small"
                >
                  {saving ? '저장 중...' : '변경'}
                </button>
              </div>
            )}
          </div>
        ) : (
          <div className="no-link-detail">
            <span className="text-muted">연결된 업무 요청이 없습니다.</span>
            {user?.is_admin && (
              <div className="link-actions-row">
                <select
                  value={selectedWorkRequestId}
                  onChange={(e) => setSelectedWorkRequestId(e.target.value)}
                  className="filter-select"
                >
                  <option value="">업무 요청 선택...</option>
                  {workRequests.map((wr) => (
                    <option key={wr.request_id} value={wr.request_id}>
                      [{wr.service_display_name}] {wr.description.substring(0, 30)}...
                    </option>
                  ))}
                </select>
                <button
                  onClick={handleLinkWorkRequest}
                  disabled={saving || !selectedWorkRequestId}
                  className="btn btn-primary btn-small"
                >
                  {saving ? '저장 중...' : '연결'}
                </button>
              </div>
            )}
          </div>
        )}
      </div>

      <div className="section">
        <div className="section-header">
          <h3>활동 로그 ({activities.length}건)</h3>
        </div>

        {activities.length > 0 ? (
          <div className="table-container">
            <table className="data-table">
              <thead>
                <tr>
                  <th>시간</th>
                  <th>API 호출</th>
                  <th>서비스</th>
                  <th>리전</th>
                  <th>IP</th>
                  <th>상세</th>
                </tr>
              </thead>
              <tbody>
                {activities.map((activity) => (
                  <tr key={activity.log_id}>
                    <td>{formatDateTime(activity.event_time)}</td>
                    <td>
                      <span className={activity.error_code ? 'text-error' : ''}>
                        {activity.event_name}
                      </span>
                      {activity.error_code && (
                        <span className="error-badge">{activity.error_code}</span>
                      )}
                    </td>
                    <td>{getServiceFromSource(activity.event_source)}</td>
                    <td>{activity.aws_region}</td>
                    <td>{activity.source_ip}</td>
                    <td>
                      <button
                        className="btn btn-small"
                        onClick={() => setSelectedActivity(activity)}
                      >
                        보기
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : (
          <div className="empty-state">활동 로그가 없습니다.</div>
        )}
      </div>

      {selectedActivity && (
        <div className="modal-overlay" onClick={() => setSelectedActivity(null)}>
          <div className="modal" onClick={(e) => e.stopPropagation()}>
            <div className="modal-header">
              <h3>활동 상세 - {selectedActivity.event_name}</h3>
              <button className="close-btn" onClick={() => setSelectedActivity(null)}>×</button>
            </div>
            <div className="modal-body">
              <div className="detail-grid">
                <div className="detail-item">
                  <label>시간</label>
                  <span>{formatDateTime(selectedActivity.event_time)}</span>
                </div>
                <div className="detail-item">
                  <label>이벤트</label>
                  <span>{selectedActivity.event_name}</span>
                </div>
                <div className="detail-item">
                  <label>서비스</label>
                  <span>{selectedActivity.event_source}</span>
                </div>
                <div className="detail-item">
                  <label>리전</label>
                  <span>{selectedActivity.aws_region}</span>
                </div>
                <div className="detail-item">
                  <label>Source IP</label>
                  <span>{selectedActivity.source_ip}</span>
                </div>
                <div className="detail-item">
                  <label>Session</label>
                  <span>{selectedActivity.session_name}</span>
                </div>
                <div className="detail-item full-width">
                  <label>User Agent</label>
                  <code className="small">{selectedActivity.user_agent}</code>
                </div>
                {selectedActivity.error_code && (
                  <>
                    <div className="detail-item">
                      <label>Error Code</label>
                      <span className="text-error">{selectedActivity.error_code}</span>
                    </div>
                    <div className="detail-item full-width">
                      <label>Error Message</label>
                      <span className="text-error">{selectedActivity.error_message}</span>
                    </div>
                  </>
                )}
              </div>
              <div className="raw-event">
                <label>Raw Event</label>
                <pre>{JSON.stringify(JSON.parse(selectedActivity.raw_event), null, 2)}</pre>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

export default TicketDetail;
