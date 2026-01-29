import React, { useEffect, useState } from 'react';
import { useNavigate, Link } from 'react-router-dom';
import { getTickets, approveTicket, rejectTicket, revokeTicket, getWorkRequestDetail, Ticket, WorkRequest } from '../api';
import { getNameByMattermost, getNameByIamUser } from '../utils/userMapping';
import { useAuth } from '../contexts/AuthContext';
import Pagination from '../components/Pagination';
import Toast from '../components/Toast';
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

const ITEMS_PER_PAGE = 20;

const AdminTicketApproval: React.FC = () => {
  const navigate = useNavigate();
  const { user } = useAuth();
  const [tickets, setTickets] = useState<Ticket[]>([]);
  const [loading, setLoading] = useState(true);
  const [statusFilter, setStatusFilter] = useState<string>('');
  const [processing, setProcessing] = useState<string | null>(null);
  const [selectedTicket, setSelectedTicket] = useState<Ticket | null>(null);
  const [rejectReason, setRejectReason] = useState('');
  const [showRejectModal, setShowRejectModal] = useState(false);
  const [currentPage, setCurrentPage] = useState(1);
  const [toast, setToast] = useState<{ message: string; type: 'success' | 'error' } | null>(null);
  const [expandedTickets, setExpandedTickets] = useState<Set<string>>(new Set());
  const [workRequestCache, setWorkRequestCache] = useState<Record<string, WorkRequest | null>>({});

  useEffect(() => {
    if (user && !user.is_admin) {
      navigate('/');
      return;
    }
    loadTickets();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [user, statusFilter]);

  useEffect(() => {
    return () => {
      document.body.classList.remove('modal-open');
    };
  }, []);

  const loadTickets = async () => {
    setLoading(true);
    try {
      const params: any = { limit: 100 };
      if (statusFilter) params.status = statusFilter;
      const data = await getTickets(params);
      setTickets(data.tickets || []);
      setCurrentPage(1);
    } catch (error) {
      console.error('Failed to load tickets:', error);
    } finally {
      setLoading(false);
    }
  };

  const toggleExpand = async (ticket: Ticket) => {
    const newExpanded = new Set(expandedTickets);
    if (newExpanded.has(ticket.request_id)) {
      newExpanded.delete(ticket.request_id);
    } else {
      newExpanded.add(ticket.request_id);
      // Load work request if needed
      if (ticket.work_request_id && !workRequestCache[ticket.work_request_id]) {
        try {
          const data = await getWorkRequestDetail(ticket.work_request_id);
          setWorkRequestCache(prev => ({
            ...prev,
            [ticket.work_request_id!]: data.work_request || null
          }));
        } catch (error) {
          console.error('Failed to load work request:', error);
          setWorkRequestCache(prev => ({
            ...prev,
            [ticket.work_request_id!]: null
          }));
        }
      }
    }
    setExpandedTickets(newExpanded);
  };

  const handleApprove = async (e: React.MouseEvent, requestId: string) => {
    e.stopPropagation();
    if (!window.confirm('이 요청을 승인하시겠습니까?')) return;

    setProcessing(requestId);
    try {
      await approveTicket(requestId);
      await loadTickets();
      setToast({ message: '승인 완료되었습니다', type: 'success' });
    } catch (error: any) {
      setToast({ message: error.response?.data?.error || '승인 처리 중 오류가 발생했습니다', type: 'error' });
    } finally {
      setProcessing(null);
    }
  };

  const handleRejectClick = (e: React.MouseEvent, ticket: Ticket) => {
    e.stopPropagation();
    setSelectedTicket(ticket);
    setRejectReason('');
    setShowRejectModal(true);
    document.body.classList.add('modal-open');
  };

  const handleRejectConfirm = async () => {
    if (!selectedTicket) return;

    setProcessing(selectedTicket.request_id);
    try {
      await rejectTicket(selectedTicket.request_id, rejectReason || '관리자에 의해 반려됨');
      setShowRejectModal(false);
      document.body.classList.remove('modal-open');
      await loadTickets();
      setToast({ message: '반려 처리되었습니다', type: 'success' });
    } catch (error: any) {
      setToast({ message: error.response?.data?.error || '반려 처리 중 오류가 발생했습니다', type: 'error' });
    } finally {
      setProcessing(null);
      setSelectedTicket(null);
    }
  };

  const handleRevoke = async (e: React.MouseEvent, ticket: Ticket) => {
    e.stopPropagation();
    if (!window.confirm(`${getNameByMattermost(ticket.requester_name)}의 권한을 회수하시겠습니까?`)) return;

    setProcessing(ticket.request_id);
    try {
      await revokeTicket(ticket.request_id);
      await loadTickets();
      setToast({ message: '권한이 회수되었습니다', type: 'success' });
    } catch (error: any) {
      setToast({ message: error.response?.data?.error || '권한 회수 중 오류가 발생했습니다', type: 'error' });
    } finally {
      setProcessing(null);
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
    });
  };

  // Pagination
  const totalItems = tickets.length;
  const totalPages = Math.ceil(totalItems / ITEMS_PER_PAGE);
  const startIndex = (currentPage - 1) * ITEMS_PER_PAGE;
  const paginatedTickets = tickets.slice(startIndex, startIndex + ITEMS_PER_PAGE);

  const handlePageChange = (page: number) => {
    setCurrentPage(page);
    window.scrollTo({ top: 0, behavior: 'smooth' });
  };

  if (!user?.is_admin) {
    return (
      <div className="page">
        <div className="form-error">관리자 권한이 필요합니다</div>
      </div>
    );
  }

  return (
    <div className="page">
      {toast && (
        <Toast
          message={toast.message}
          type={toast.type}
          onClose={() => setToast(null)}
        />
      )}

      <div className="page-header">
        <h2>권한 승인/반려 <span className="admin-badge-inline">Admin</span></h2>
        <p className="page-description">권한 요청을 승인하거나 반려합니다.</p>
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
            <option value="pending">승인대기</option>
            <option value="approved">승인됨</option>
            <option value="active">활성</option>
            <option value="expired">만료됨</option>
            <option value="revoked">회수됨</option>
            <option value="rejected">반려됨</option>
          </select>
        </div>
        <button onClick={loadTickets} className="btn btn-primary">새로고침</button>
      </div>

      {loading ? (
        <div className="loading">로딩 중...</div>
      ) : (
        <div className="accordion-list">
          {paginatedTickets.map((ticket) => {
            const isExpanded = expandedTickets.has(ticket.request_id);
            const workRequest = ticket.work_request_id ? workRequestCache[ticket.work_request_id] : null;

            return (
              <div key={ticket.request_id} className={`accordion-item ${isExpanded ? 'expanded' : ''}`}>
                <div className="accordion-header" onClick={() => toggleExpand(ticket)}>
                  <div className="accordion-header-left">
                    <span className="accordion-toggle">{isExpanded ? '▼' : '▶'}</span>
                    <span
                      className="status-badge"
                      style={{ backgroundColor: statusColors[ticket.status] || '#6b7280' }}
                    >
                      {statusLabels[ticket.status] || ticket.status}
                    </span>
                    <span className="accordion-requester">{getNameByMattermost(ticket.requester_name)}</span>
                    <span className="accordion-env">{ticket.env} / {ticket.service}</span>
                    <span className="accordion-permission">{permissionLabels[ticket.permission_type] || ticket.permission_type}</span>
                    <span className="accordion-date">{formatDateTime(ticket.created_at)}</span>
                  </div>
                  <div className="accordion-header-right">
                    {ticket.status === 'pending' && (
                      <>
                        <button
                          className="action-btn-approve"
                          onClick={(e) => handleApprove(e, ticket.request_id)}
                          disabled={processing === ticket.request_id}
                        >
                          승인
                        </button>
                        <button
                          className="action-btn-reject"
                          onClick={(e) => handleRejectClick(e, ticket)}
                          disabled={processing === ticket.request_id}
                        >
                          반려
                        </button>
                      </>
                    )}
                    {(ticket.status === 'active' || ticket.status === 'approved') && (
                      <button
                        className="action-btn-revoke"
                        onClick={(e) => handleRevoke(e, ticket)}
                        disabled={processing === ticket.request_id}
                      >
                        회수
                      </button>
                    )}
                  </div>
                </div>
                {isExpanded && (
                  <div className="accordion-content">
                    <div className="accordion-content-header">
                      <Link
                        to={`/tickets/${ticket.request_id}?from=admin-approval`}
                        className="accordion-detail-link"
                      >
                        상세보기 →
                      </Link>
                    </div>
                    <div className="accordion-detail-grid">
                      <div className="accordion-detail-item">
                        <label>IAM User</label>
                        <span>{getNameByIamUser(ticket.iam_user_name)}</span>
                      </div>
                      <div className="accordion-detail-item">
                        <label>대상 서비스</label>
                        <span>{ticket.target_services?.join(', ') || 'all'}</span>
                      </div>
                      <div className="accordion-detail-item">
                        <label>시작 시간</label>
                        <span>{formatDateTime(ticket.start_time)}</span>
                      </div>
                      <div className="accordion-detail-item">
                        <label>종료 시간</label>
                        <span>{formatDateTime(ticket.end_time)}</span>
                      </div>
                      <div className="accordion-detail-item full-width">
                        <label>목적</label>
                        <span>{ticket.purpose}</span>
                      </div>
                      {ticket.role_arn && (
                        <div className="accordion-detail-item full-width">
                          <label>Role ARN</label>
                          <code>{ticket.role_arn}</code>
                        </div>
                      )}
                    </div>

                    {/* 연관 업무 요청 */}
                    <div className="accordion-work-request">
                      <h4>연관 업무 요청</h4>
                      {ticket.work_request_id ? (
                        workRequest ? (
                          <div className="work-request-info">
                            <div className="work-request-row">
                              <span className="work-request-service">{workRequest.service_display_name}</span>
                              <span className="work-request-period">{workRequest.start_date} ~ {workRequest.end_date}</span>
                              <span className="work-request-requester">{workRequest.requester_name}</span>
                            </div>
                            <div className="work-request-desc">{workRequest.description}</div>
                          </div>
                        ) : (
                          <span className="text-muted">로딩 중...</span>
                        )
                      ) : (
                        <span className="text-muted">연결된 업무 요청이 없습니다</span>
                      )}
                    </div>
                  </div>
                )}
              </div>
            );
          })}
          {tickets.length === 0 && (
            <div className="empty-state">데이터가 없습니다.</div>
          )}
          <Pagination
            currentPage={currentPage}
            totalPages={totalPages}
            onPageChange={handlePageChange}
            totalItems={totalItems}
            itemsPerPage={ITEMS_PER_PAGE}
          />
        </div>
      )}

      {/* Reject Modal */}
      {showRejectModal && selectedTicket && (
        <div className="modal-overlay" onClick={() => { setShowRejectModal(false); document.body.classList.remove('modal-open'); }}>
          <div className="modal" onClick={(e) => e.stopPropagation()}>
            <div className="modal-header">
              <h3>반려 사유 입력</h3>
              <button className="close-btn" onClick={() => { setShowRejectModal(false); document.body.classList.remove('modal-open'); }}>×</button>
            </div>
            <div className="modal-body">
              <div className="detail-grid">
                <div className="detail-item">
                  <label>요청자</label>
                  <span>{getNameByMattermost(selectedTicket.requester_name)}</span>
                </div>
                <div className="detail-item">
                  <label>IAM User</label>
                  <span>{selectedTicket.iam_user_name}</span>
                </div>
                <div className="detail-item full-width">
                  <label>목적</label>
                  <span>{selectedTicket.purpose}</span>
                </div>
              </div>
              <div className="form-group" style={{ marginTop: '16px' }}>
                <label htmlFor="rejectReason">반려 사유</label>
                <textarea
                  id="rejectReason"
                  value={rejectReason}
                  onChange={(e) => setRejectReason(e.target.value)}
                  placeholder="반려 사유를 입력하세요 (선택)"
                  className="form-textarea"
                  rows={3}
                />
              </div>
              <div className="form-actions">
                <button
                  className="btn btn-secondary"
                  onClick={() => { setShowRejectModal(false); document.body.classList.remove('modal-open'); }}
                >
                  취소
                </button>
                <button
                  className="btn btn-danger"
                  onClick={handleRejectConfirm}
                  disabled={processing === selectedTicket.request_id}
                >
                  반려 확인
                </button>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

export default AdminTicketApproval;
