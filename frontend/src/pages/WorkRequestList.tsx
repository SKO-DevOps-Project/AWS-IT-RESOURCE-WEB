import React, { useEffect, useState } from 'react';
import { Link, useSearchParams } from 'react-router-dom';
import { getWorkRequests, updateWorkRequestStatus, getWorkRequestTickets, WorkRequest, Ticket } from '../api';
import { getNameByMattermost } from '../utils/userMapping';
import { useAuth } from '../contexts/AuthContext';
import './Pages.css';

const statusColors: Record<string, string> = {
  pending: '#f59e0b',
  in_progress: '#3b82f6',
  completed: '#10b981',
  cancelled: '#ef4444',
};

const statusLabels: Record<string, string> = {
  pending: '대기중',
  in_progress: '진행중',
  completed: '완료',
  cancelled: '취소됨',
};

const ticketStatusColors: Record<string, string> = {
  pending: '#f59e0b',
  approved: '#3b82f6',
  active: '#10b981',
  expired: '#6b7280',
  revoked: '#ef4444',
  rejected: '#ef4444',
  error: '#ef4444',
};

const ticketStatusLabels: Record<string, string> = {
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

const WorkRequestList: React.FC = () => {
  const { user } = useAuth();
  const [searchParams] = useSearchParams();
  const [workRequests, setWorkRequests] = useState<WorkRequest[]>([]);
  const [loading, setLoading] = useState(true);
  const [serviceFilter, setServiceFilter] = useState<string>('');
  const [statusFilter, setStatusFilter] = useState<string>(searchParams.get('status') || '');
  const [selectedRequest, setSelectedRequest] = useState<WorkRequest | null>(null);
  const [linkedTickets, setLinkedTickets] = useState<Ticket[]>([]);
  const [loadingTickets, setLoadingTickets] = useState(false);
  const [updating, setUpdating] = useState(false);
  const [expandedTicketIds, setExpandedTicketIds] = useState<Set<string>>(new Set());

  useEffect(() => {
    const status = searchParams.get('status');
    if (status) {
      setStatusFilter(status);
    }
    loadWorkRequests();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [searchParams]);

  const loadWorkRequests = async () => {
    setLoading(true);
    try {
      const params: any = { limit: 100 };
      if (serviceFilter) params.service_name = serviceFilter;
      if (statusFilter) params.status = statusFilter;
      const data = await getWorkRequests(params);
      setWorkRequests(data.work_requests || []);
    } catch (error) {
      console.error('Failed to load work requests:', error);
    } finally {
      setLoading(false);
    }
  };

  const handleReset = () => {
    setServiceFilter('');
    setStatusFilter('');
  };

  const handleSelectRequest = async (request: WorkRequest) => {
    setSelectedRequest(request);
    setLoadingTickets(true);
    try {
      const data = await getWorkRequestTickets(request.request_id);
      setLinkedTickets(data.tickets || []);
    } catch (error) {
      console.error('Failed to load linked tickets:', error);
      setLinkedTickets([]);
    } finally {
      setLoadingTickets(false);
    }
  };

  const handleCloseModal = () => {
    setSelectedRequest(null);
    setLinkedTickets([]);
    setExpandedTicketIds(new Set());
  };

  const toggleTicketExpand = (ticketId: string) => {
    setExpandedTicketIds(prev => {
      const newSet = new Set(prev);
      if (newSet.has(ticketId)) {
        newSet.delete(ticketId);
      } else {
        newSet.add(ticketId);
      }
      return newSet;
    });
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
    });
  };

  const formatDate = (dateString: string) => {
    const date = new Date(dateString);
    return date.toLocaleDateString('ko-KR', {
      timeZone: 'Asia/Seoul',
      year: 'numeric',
      month: '2-digit',
      day: '2-digit',
    });
  };

  const handleStatusChange = async (requestId: string, newStatus: string) => {
    setUpdating(true);
    try {
      await updateWorkRequestStatus(requestId, newStatus);
      // 목록 새로고침
      await loadWorkRequests();
      // 모달의 선택된 항목도 업데이트
      if (selectedRequest && selectedRequest.request_id === requestId) {
        setSelectedRequest({ ...selectedRequest, status: newStatus });
      }
    } catch (error) {
      console.error('Failed to update status:', error);
      alert('상태 변경에 실패했습니다.');
    } finally {
      setUpdating(false);
    }
  };

  return (
    <div className="page">
      <div className="page-header">
        <h2>업무 요청</h2>
        <p className="page-description">업무 요청 내역을 확인합니다.</p>
      </div>

      <div className="filters">
        <div className="filter-group">
          <label>상태</label>
          <select
            value={statusFilter}
            onChange={(e) => setStatusFilter(e.target.value)}
            className="filter-select"
          >
            <option value="">전체</option>
            <option value="pending">대기중</option>
            <option value="in_progress">진행중</option>
            <option value="completed">완료</option>
            <option value="cancelled">취소됨</option>
          </select>
        </div>
        <div className="filter-group">
          <label>서비스</label>
          <input
            type="text"
            placeholder="서비스명"
            value={serviceFilter}
            onChange={(e) => setServiceFilter(e.target.value)}
            onKeyDown={(e) => e.key === 'Enter' && loadWorkRequests()}
            className="filter-input"
          />
        </div>
        <button onClick={loadWorkRequests} className="btn btn-primary">검색</button>
        <button onClick={handleReset} className="btn btn-secondary">초기화</button>
      </div>

      {loading ? (
        <div className="loading">로딩 중...</div>
      ) : (
        <div className="table-container">
          <table className="data-table">
            <thead>
              <tr>
                <th>상태</th>
                <th>서비스</th>
                <th>요청자</th>
                <th>작업 기간</th>
                <th>작업 내용</th>
                <th>요청일시</th>
              </tr>
            </thead>
            <tbody>
              {workRequests.map((request) => (
                <tr
                  key={request.request_id}
                  onClick={() => handleSelectRequest(request)}
                  className="clickable-row"
                >
                  <td>
                    <span
                      className="status-badge"
                      style={{ backgroundColor: statusColors[request.status] || '#6b7280' }}
                    >
                      {statusLabels[request.status] || request.status}
                    </span>
                  </td>
                  <td>
                    <div>{request.service_name}</div>
                    <div className="text-muted">{request.service_display_name}</div>
                  </td>
                  <td>{request.requester_name}</td>
                  <td className="date-cell">
                    <div>{formatDate(request.start_date)}</div>
                    <div className="text-muted">~ {formatDate(request.end_date)}</div>
                  </td>
                  <td className="purpose-cell" title={request.description}>{request.description}</td>
                  <td className="date-cell">{formatDateTime(request.created_at)}</td>
                </tr>
              ))}
            </tbody>
          </table>
          {workRequests.length === 0 && (
            <div className="empty-state">데이터가 없습니다.</div>
          )}
        </div>
      )}

      {selectedRequest && (
        <div className="modal-overlay" onClick={handleCloseModal}>
          <div className="modal modal-large" onClick={(e) => e.stopPropagation()}>
            <div className="modal-header">
              <h3>업무 요청 상세</h3>
              <button className="close-btn" onClick={handleCloseModal}>×</button>
            </div>
            <div className="modal-body">
              <div className="detail-grid">
                <div className="detail-item">
                  <label>상태</label>
                  {user?.is_admin ? (
                    <div className="status-select-wrapper" data-label={statusLabels[selectedRequest.status]}>
                      <span
                        className="status-indicator"
                        style={{ backgroundColor: statusColors[selectedRequest.status] }}
                      />
                      <select
                        value={selectedRequest.status}
                        onChange={(e) => handleStatusChange(selectedRequest.request_id, e.target.value)}
                        disabled={updating}
                        className="status-select-styled"
                      >
                        <option value="pending">대기중</option>
                        <option value="in_progress">진행중</option>
                        <option value="completed">완료</option>
                        <option value="cancelled">취소됨</option>
                      </select>
                    </div>
                  ) : (
                    <span
                      className="status-badge"
                      style={{ backgroundColor: statusColors[selectedRequest.status] || '#6b7280' }}
                    >
                      {statusLabels[selectedRequest.status] || selectedRequest.status}
                    </span>
                  )}
                </div>
                <div className="detail-item">
                  <label>요청자</label>
                  <span>{selectedRequest.requester_name}</span>
                </div>
                <div className="detail-item">
                  <label>서비스</label>
                  <span>{selectedRequest.service_name} ({selectedRequest.service_display_name})</span>
                </div>
                <div className="detail-item">
                  <label>요청일시</label>
                  <span>{formatDateTime(selectedRequest.created_at)}</span>
                </div>
                <div className="detail-item">
                  <label>작업 시작일</label>
                  <span>{formatDate(selectedRequest.start_date)}</span>
                </div>
                <div className="detail-item">
                  <label>작업 종료일</label>
                  <span>{formatDate(selectedRequest.end_date)}</span>
                </div>
                <div className="detail-item full-width">
                  <label>작업 내용</label>
                  <div className="description-box">{selectedRequest.description}</div>
                </div>
                <div className="detail-item full-width">
                  <label>요청 ID</label>
                  <code>{selectedRequest.request_id}</code>
                </div>
              </div>

              {/* 연결된 업무 권한 요청 목록 */}
              <div className="linked-tickets-section">
                <h4>연결된 업무 권한 요청 ({linkedTickets.length}건)</h4>
                {loadingTickets ? (
                  <div className="loading-small">로딩 중...</div>
                ) : linkedTickets.length > 0 ? (
                  <div className="linked-tickets-list">
                    {linkedTickets.map((ticket) => (
                      <div
                        key={ticket.request_id}
                        className={`accordion-ticket-item ${expandedTicketIds.has(ticket.request_id) ? 'expanded' : ''}`}
                      >
                        <div
                          className="accordion-ticket-header"
                          onClick={() => toggleTicketExpand(ticket.request_id)}
                        >
                          <span
                            className="status-badge small"
                            style={{ backgroundColor: ticketStatusColors[ticket.status] || '#6b7280' }}
                          >
                            {ticketStatusLabels[ticket.status] || ticket.status}
                          </span>
                          <span className="ticket-info">
                            <strong>{getNameByMattermost(ticket.requester_name)}</strong> - {ticket.env}/{ticket.service}
                          </span>
                          <span className="ticket-permission">{permissionLabels[ticket.permission_type] || ticket.permission_type}</span>
                          <span className="ticket-date">{formatDateTime(ticket.created_at)}</span>
                          <span className="accordion-arrow">{expandedTicketIds.has(ticket.request_id) ? '▲' : '▼'}</span>
                        </div>
                        {expandedTicketIds.has(ticket.request_id) && (
                          <div className="accordion-ticket-body">
                            <div className="accordion-ticket-grid">
                              <div className="accordion-ticket-field">
                                <label>요청자</label>
                                <span>{getNameByMattermost(ticket.requester_name)}</span>
                              </div>
                              <div className="accordion-ticket-field">
                                <label>IAM User</label>
                                <span>{ticket.iam_user_name}</span>
                              </div>
                              <div className="accordion-ticket-field">
                                <label>Environment</label>
                                <span>{ticket.env}</span>
                              </div>
                              <div className="accordion-ticket-field">
                                <label>Service</label>
                                <span>{ticket.service}</span>
                              </div>
                              <div className="accordion-ticket-field">
                                <label>권한 유형</label>
                                <span>{permissionLabels[ticket.permission_type] || ticket.permission_type}</span>
                              </div>
                              <div className="accordion-ticket-field">
                                <label>대상 서비스</label>
                                <span>{ticket.target_services?.join(', ') || 'all'}</span>
                              </div>
                              <div className="accordion-ticket-field">
                                <label>시작 시간</label>
                                <span>{formatDateTime(ticket.start_time)}</span>
                              </div>
                              <div className="accordion-ticket-field">
                                <label>종료 시간</label>
                                <span>{formatDateTime(ticket.end_time)}</span>
                              </div>
                              <div className="accordion-ticket-field full-width">
                                <label>목적</label>
                                <span>{ticket.purpose}</span>
                              </div>
                            </div>
                            <div className="accordion-ticket-actions">
                              <Link to={`/tickets/${ticket.request_id}`} className="btn btn-small btn-primary">
                                상세 보기 →
                              </Link>
                            </div>
                          </div>
                        )}
                      </div>
                    ))}
                  </div>
                ) : (
                  <div className="empty-state-small">연결된 업무 권한 요청이 없습니다.</div>
                )}
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

export default WorkRequestList;
