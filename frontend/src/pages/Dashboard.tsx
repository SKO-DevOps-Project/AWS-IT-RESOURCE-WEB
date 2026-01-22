import React, { useEffect, useState } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import { getTickets, getWorkRequests, getActivities, Ticket, WorkRequest, Activity } from '../api';
import { getNameByMattermost, getNameByIamUser } from '../utils/userMapping';
import { useAuth } from '../contexts/AuthContext';
import './Dashboard.css';

const statusColors: Record<string, string> = {
  pending: '#f59e0b',
  approved: '#3b82f6',
  active: '#10b981',
  expired: '#6b7280',
  revoked: '#ef4444',
  rejected: '#ef4444',
  error: '#ef4444',
  in_progress: '#3b82f6',
  completed: '#10b981',
  cancelled: '#ef4444',
};

const statusLabels: Record<string, string> = {
  pending: '승인대기',
  approved: '승인됨',
  active: '활성',
  expired: '만료됨',
  revoked: '회수됨',
  rejected: '반려됨',
  error: '오류',
  in_progress: '진행중',
  completed: '완료',
  cancelled: '취소됨',
};

interface DashboardStats {
  totalWorkRequests: number;
  pendingWorkRequests: number;
  inProgressWorkRequests: number;
  activeTickets: number;
}

const Dashboard: React.FC = () => {
  const { user } = useAuth();
  const navigate = useNavigate();
  const [stats, setStats] = useState<DashboardStats>({
    totalWorkRequests: 0,
    pendingWorkRequests: 0,
    inProgressWorkRequests: 0,
    activeTickets: 0,
  });
  const [recentTickets, setRecentTickets] = useState<Ticket[]>([]);
  const [pendingTickets, setPendingTickets] = useState<Ticket[]>([]);
  const [recentWorkRequests, setRecentWorkRequests] = useState<WorkRequest[]>([]);
  const [recentActivityLogs, setRecentActivityLogs] = useState<Activity[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    loadDashboardData();
  }, []);

  const loadDashboardData = async () => {
    setLoading(true);
    try {
      const [ticketsData, workRequestsData, activitiesData] = await Promise.all([
        getTickets({ limit: 100 }),
        getWorkRequests({ limit: 100 }),
        getActivities({ limit: 10 }),
      ]);

      const tickets = ticketsData.tickets || [];
      const workRequests = workRequestsData.work_requests || [];
      const activities = activitiesData.activities || [];

      // Calculate stats
      const pending = tickets.filter((t: Ticket) => t.status === 'pending');
      const active = tickets.filter((t: Ticket) => t.status === 'active');
      const pendingWR = workRequests.filter((w: WorkRequest) => w.status === 'pending');
      const inProgressWR = workRequests.filter((w: WorkRequest) => w.status === 'in_progress');

      setStats({
        totalWorkRequests: workRequests.length,
        pendingWorkRequests: pendingWR.length,
        inProgressWorkRequests: inProgressWR.length,
        activeTickets: active.length,
      });

      // Recent items
      setRecentTickets(tickets.slice(0, 5));
      setPendingTickets(pending.slice(0, 5));
      setRecentWorkRequests(workRequests.slice(0, 5));
      setRecentActivityLogs(activities.slice(0, 5));
    } catch (error) {
      console.error('Failed to load dashboard data:', error);
    } finally {
      setLoading(false);
    }
  };

  const formatDateTime = (isoString: string) => {
    const date = new Date(isoString);
    return date.toLocaleString('ko-KR', {
      timeZone: 'Asia/Seoul',
      month: '2-digit',
      day: '2-digit',
      hour: '2-digit',
      minute: '2-digit',
    });
  };

  const getGreeting = () => {
    const hour = new Date().getHours();
    if (hour < 12) return '좋은 아침이에요';
    if (hour < 18) return '좋은 오후에요';
    return '좋은 저녁이에요';
  };

  if (loading) {
    return (
      <div className="dashboard">
        <div className="dashboard-loading">
          <div className="loading-spinner"></div>
          <span>대시보드를 불러오는 중...</span>
        </div>
      </div>
    );
  }

  return (
    <div className="dashboard">
      {/* Header */}
      <div className="dashboard-header">
        <div className="greeting">
          <h1>{getGreeting()}, <span className="user-name-highlight">{user?.name}</span>님</h1>
          <p>서버 접근통제 시스템 현황을 확인하세요.</p>
        </div>
        <div className="header-date">
          {new Date().toLocaleDateString('ko-KR', {
            year: 'numeric',
            month: 'long',
            day: 'numeric',
            weekday: 'long',
          })}
        </div>
      </div>

      {/* Stats Cards */}
      <div className="stats-grid">
        <div className="stat-card clickable" title="전체 업무 요청 건수" onClick={() => navigate('/work-requests')}>
          <div className="stat-icon total">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
              <path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/>
              <polyline points="14,2 14,8 20,8"/>
              <line x1="16" y1="13" x2="8" y2="13"/>
              <line x1="16" y1="17" x2="8" y2="17"/>
            </svg>
          </div>
          <div className="stat-content">
            <span className="stat-value">{stats.totalWorkRequests}</span>
            <span className="stat-label">전체 업무</span>
          </div>
        </div>
        <div className="stat-card clickable" title="승인 대기 중인 업무 요청 수" onClick={() => navigate('/work-requests?status=pending')}>
          <div className="stat-icon pending">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
              <circle cx="12" cy="12" r="10"/>
              <path d="M12 6v6l4 2"/>
            </svg>
          </div>
          <div className="stat-content">
            <span className="stat-value">{stats.pendingWorkRequests}</span>
            <span className="stat-label">대기중 업무</span>
          </div>
        </div>
        <div className="stat-card clickable" title="진행 중인 업무 요청 수" onClick={() => navigate('/work-requests?status=in_progress')}>
          <div className="stat-icon work">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
              <rect x="2" y="7" width="20" height="14" rx="2" ry="2"/>
              <path d="M16 21V5a2 2 0 0 0-2-2h-4a2 2 0 0 0-2 2v16"/>
            </svg>
          </div>
          <div className="stat-content">
            <span className="stat-value">{stats.inProgressWorkRequests}</span>
            <span className="stat-label">진행중 업무</span>
          </div>
        </div>
        <div className="stat-card clickable" title="현재 활성화된 AWS Role 권한 수" onClick={() => navigate('/role-requests?status=active')}>
          <div className="stat-icon active">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
              <path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"/>
              <polyline points="22,4 12,14.01 9,11.01"/>
            </svg>
          </div>
          <div className="stat-content">
            <span className="stat-value">{stats.activeTickets}</span>
            <span className="stat-label">활성 권한</span>
          </div>
        </div>
      </div>

      {/* Main Content Grid */}
      <div className="dashboard-grid">
        {/* Pending Approvals - Admin Only */}
        {user?.is_admin && pendingTickets.length > 0 && (
          <div className="dashboard-card urgent">
            <div className="card-header">
              <h3>승인 대기 요청</h3>
              <Link to="/role-requests" className="view-all">전체 보기 →</Link>
            </div>
            <div className="card-body">
              <div className="pending-list">
                {pendingTickets.map((ticket) => (
                  <Link to={`/tickets/${ticket.request_id}`} key={ticket.request_id} className="pending-item">
                    <div className="pending-info">
                      <span className="pending-requester">{getNameByMattermost(ticket.requester_name)}</span>
                      <span className="pending-detail">{ticket.env}/{ticket.service} • {ticket.permission_type}</span>
                    </div>
                    <span className="pending-time">{formatDateTime(ticket.created_at)}</span>
                  </Link>
                ))}
              </div>
            </div>
          </div>
        )}

        {/* Recent Work Requests */}
        <div className="dashboard-card">
          <div className="card-header">
            <h3>최근 업무 요청</h3>
            <Link to="/work-requests" className="view-all">전체 보기 →</Link>
          </div>
          <div className="card-body">
            <div className="recent-list">
              {recentWorkRequests.map((wr) => (
                <div key={wr.request_id} className="recent-item">
                  <span
                    className="status-dot"
                    style={{ backgroundColor: statusColors[wr.status] }}
                  />
                  <div className="recent-info">
                    <span className="recent-title">{wr.service_display_name}</span>
                    <span className="recent-subtitle">{wr.description}</span>
                  </div>
                  <span
                    className="recent-status"
                    style={{ color: statusColors[wr.status] }}
                  >
                    {statusLabels[wr.status]}
                  </span>
                </div>
              ))}
              {recentWorkRequests.length === 0 && (
                <div className="empty-message">최근 업무 요청이 없습니다.</div>
              )}
            </div>
          </div>
        </div>

        {/* Recent Role Requests */}
        <div className="dashboard-card">
          <div className="card-header">
            <h3>최근 권한 요청</h3>
            <Link to="/role-requests" className="view-all">전체 보기 →</Link>
          </div>
          <div className="card-body">
            <div className="recent-list">
              {recentTickets.map((ticket) => (
                <Link to={`/tickets/${ticket.request_id}`} key={ticket.request_id} className="recent-item">
                  <span
                    className="status-dot"
                    style={{ backgroundColor: statusColors[ticket.status] }}
                  />
                  <div className="recent-info">
                    <span className="recent-title">{getNameByMattermost(ticket.requester_name)}</span>
                    <span className="recent-subtitle">{ticket.env}/{ticket.service}</span>
                  </div>
                  <span
                    className="recent-status"
                    style={{ color: statusColors[ticket.status] }}
                  >
                    {statusLabels[ticket.status]}
                  </span>
                </Link>
              ))}
              {recentTickets.length === 0 && (
                <div className="empty-message">최근 요청이 없습니다.</div>
              )}
            </div>
          </div>
        </div>

        {/* Recent Activity Logs - Full Width */}
        <div className="dashboard-card full-width">
          <div className="card-header">
            <h3>최근 권한 활동</h3>
            <Link to="/activities" className="view-all">전체 보기 →</Link>
          </div>
          <div className="card-body">
            <div className="activity-table">
              <div className="activity-table-header">
                <span>시간</span>
                <span>사용자</span>
                <span>이벤트</span>
                <span>서비스</span>
                <span>리전</span>
                <span>IP</span>
              </div>
              {recentActivityLogs.map((activity) => (
                <div key={activity.log_id} className={`activity-table-row ${activity.error_code ? 'has-error' : ''}`}>
                  <span className="activity-cell time">{formatDateTime(activity.event_time)}</span>
                  <span className="activity-cell user">{getNameByIamUser(activity.iam_user_name)}</span>
                  <span className="activity-cell event">{activity.event_name}</span>
                  <span className="activity-cell service">{activity.event_source.split('.')[0].toUpperCase()}</span>
                  <span className="activity-cell region">{activity.aws_region}</span>
                  <span className="activity-cell ip">{activity.source_ip}</span>
                </div>
              ))}
              {recentActivityLogs.length === 0 && (
                <div className="empty-message">최근 활동이 없습니다.</div>
              )}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};

export default Dashboard;
