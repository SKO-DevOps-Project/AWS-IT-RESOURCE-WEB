import React, { useEffect, useState } from 'react';
import { useNavigate, useSearchParams } from 'react-router-dom';
import { getTickets, Ticket } from '../api';
import { getNameByMattermost, getNameByIamUser, iamUserList } from '../utils/userMapping';
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

const TicketList: React.FC = () => {
  const navigate = useNavigate();
  const [searchParams] = useSearchParams();
  const [tickets, setTickets] = useState<Ticket[]>([]);
  const [loading, setLoading] = useState(true);
  const [statusFilter, setStatusFilter] = useState<string>(searchParams.get('status') || '');
  const [userFilter, setUserFilter] = useState<string>('');
  const [startDate, setStartDate] = useState<string>('');
  const [endDate, setEndDate] = useState<string>('');
  const [showUserDropdown, setShowUserDropdown] = useState(false);

  const handleRowClick = (requestId: string) => {
    navigate(`/tickets/${requestId}`);
  };

  useEffect(() => {
    const status = searchParams.get('status');
    if (status) {
      setStatusFilter(status);
    }
    loadTickets();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [searchParams]);

  const loadTickets = async () => {
    setLoading(true);
    try {
      const params: any = { limit: 100 };
      if (statusFilter) params.status = statusFilter;
      const data = await getTickets(params);
      let filteredTickets = data.tickets || [];

      // Client-side filters
      if (userFilter) {
        filteredTickets = filteredTickets.filter((t: Ticket) =>
          t.iam_user_name.toLowerCase().includes(userFilter.toLowerCase()) ||
          t.requester_name.toLowerCase().includes(userFilter.toLowerCase()) ||
          getNameByMattermost(t.requester_name).includes(userFilter) ||
          getNameByIamUser(t.iam_user_name).includes(userFilter)
        );
      }

      // Date range filter
      if (startDate) {
        const start = new Date(startDate);
        filteredTickets = filteredTickets.filter((t: Ticket) => new Date(t.created_at) >= start);
      }
      if (endDate) {
        const end = new Date(endDate);
        end.setHours(23, 59, 59, 999);
        filteredTickets = filteredTickets.filter((t: Ticket) => new Date(t.created_at) <= end);
      }

      setTickets(filteredTickets);
    } catch (error) {
      console.error('Failed to load tickets:', error);
    } finally {
      setLoading(false);
    }
  };

  const handleReset = () => {
    setStatusFilter('');
    setUserFilter('');
    setStartDate('');
    setEndDate('');
  };

  const handleUserSelect = (iamUser: string) => {
    setUserFilter(iamUser);
    setShowUserDropdown(false);
  };

  // 드롭다운에 표시할 필터링된 사용자 목록
  const filteredUserList = iamUserList.filter(
    (user) =>
      user.name.includes(userFilter) ||
      user.iamUser.toLowerCase().includes(userFilter.toLowerCase())
  );

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

  return (
    <div className="page">
      <div className="page-header">
        <h2>업무 권한 요청</h2>
        <p className="page-description">AWS Role 권한 요청 내역을 확인합니다.</p>
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
        <div className="filter-group user-filter-container">
          <label>사용자</label>
          <input
            type="text"
            placeholder="IAM 사용자 검색..."
            value={userFilter}
            onChange={(e) => {
              setUserFilter(e.target.value);
              setShowUserDropdown(true);
            }}
            onFocus={() => setShowUserDropdown(true)}
            onKeyDown={(e) => {
              if (e.key === 'Enter') {
                loadTickets();
                setShowUserDropdown(false);
              }
            }}
            className="filter-input"
          />
          {showUserDropdown && (
            <div className="user-dropdown">
              {filteredUserList.map((user) => (
                <div
                  key={user.iamUser}
                  className="user-dropdown-item"
                  onClick={() => handleUserSelect(user.iamUser)}
                >
                  {user.name}({user.iamUser})
                </div>
              ))}
              {filteredUserList.length === 0 && (
                <div className="user-dropdown-empty">일치하는 사용자가 없습니다</div>
              )}
            </div>
          )}
        </div>
        <div className="filter-group">
          <label>시작일</label>
          <input
            type="datetime-local"
            value={startDate}
            onChange={(e) => setStartDate(e.target.value)}
          />
        </div>
        <div className="filter-group">
          <label>종료일</label>
          <input
            type="datetime-local"
            value={endDate}
            onChange={(e) => setEndDate(e.target.value)}
          />
        </div>
        <button onClick={() => { loadTickets(); setShowUserDropdown(false); }} className="btn btn-primary">검색</button>
        <button onClick={handleReset} className="btn btn-secondary">초기화</button>
      </div>

      {/* 클릭 외부 영역 클릭시 드롭다운 닫기 */}
      {showUserDropdown && (
        <div className="dropdown-overlay" onClick={() => setShowUserDropdown(false)} />
      )}

      {loading ? (
        <div className="loading">로딩 중...</div>
      ) : (
        <div className="table-container">
          <table className="data-table">
            <thead>
              <tr>
                <th>상태</th>
                <th>요청자</th>
                <th>IAM User</th>
                <th>Env / Service</th>
                <th>권한</th>
                <th>기간</th>
                <th>목적</th>
                <th>요청일시</th>
              </tr>
            </thead>
            <tbody>
              {tickets.map((ticket) => (
                <tr
                  key={ticket.request_id}
                  onClick={() => handleRowClick(ticket.request_id)}
                  className="clickable-row"
                >
                  <td>
                    <span
                      className="status-badge"
                      style={{ backgroundColor: statusColors[ticket.status] || '#6b7280' }}
                    >
                      {statusLabels[ticket.status] || ticket.status}
                    </span>
                  </td>
                  <td>{getNameByMattermost(ticket.requester_name)}</td>
                  <td>{getNameByIamUser(ticket.iam_user_name)}</td>
                  <td>{ticket.env} / {ticket.service}</td>
                  <td>{permissionLabels[ticket.permission_type] || ticket.permission_type}</td>
                  <td className="date-cell">
                    <div>{formatDateTime(ticket.start_time)}</div>
                    <div className="text-muted">~ {formatDateTime(ticket.end_time)}</div>
                  </td>
                  <td className="purpose-cell" title={ticket.purpose}>{ticket.purpose}</td>
                  <td className="date-cell">{formatDateTime(ticket.created_at)}</td>
                </tr>
              ))}
            </tbody>
          </table>
          {tickets.length === 0 && (
            <div className="empty-state">데이터가 없습니다.</div>
          )}
        </div>
      )}
    </div>
  );
};

export default TicketList;
