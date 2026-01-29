import React, { useEffect, useState } from 'react';
import { getActivities, Activity } from '../api';
import { iamUserList, getNameByIamUser } from '../utils/userMapping';
import Pagination from '../components/Pagination';
import './Pages.css';

const ITEMS_PER_PAGE = 20;

const ActivityList: React.FC = () => {
  const [activities, setActivities] = useState<Activity[]>([]);
  const [loading, setLoading] = useState(true);
  const [userFilter, setUserFilter] = useState<string>('');
  const [eventFilter, setEventFilter] = useState<string>('');
  const [startDate, setStartDate] = useState<string>('');
  const [endDate, setEndDate] = useState<string>('');
  const [selectedActivity, setSelectedActivity] = useState<Activity | null>(null);
  const [showUserDropdown, setShowUserDropdown] = useState(false);
  const [currentPage, setCurrentPage] = useState(1);

  useEffect(() => {
    loadActivities();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  // 컴포넌트 unmount 시 modal-open 클래스 제거
  useEffect(() => {
    return () => {
      document.body.classList.remove('modal-open');
    };
  }, []);

  const loadActivities = async () => {
    setLoading(true);
    try {
      const params: any = { limit: 200 };
      if (userFilter) params.user_name = userFilter;
      if (eventFilter) params.event_name = eventFilter;
      const data = await getActivities(params);
      let filteredActivities = data.activities || [];

      // Client-side date range filter
      if (startDate) {
        const start = new Date(startDate);
        filteredActivities = filteredActivities.filter((a: Activity) => new Date(a.event_time) >= start);
      }
      if (endDate) {
        const end = new Date(endDate);
        end.setHours(23, 59, 59, 999);
        filteredActivities = filteredActivities.filter((a: Activity) => new Date(a.event_time) <= end);
      }

      setActivities(filteredActivities);
    } catch (error) {
      console.error('Failed to load activities:', error);
    } finally {
      setLoading(false);
    }
  };

  const handleReset = () => {
    setUserFilter('');
    setEventFilter('');
    setStartDate('');
    setEndDate('');
    setCurrentPage(1);
  };

  // 페이지네이션 계산
  const totalItems = activities.length;
  const totalPages = Math.ceil(totalItems / ITEMS_PER_PAGE);
  const startIndex = (currentPage - 1) * ITEMS_PER_PAGE;
  const paginatedActivities = activities.slice(startIndex, startIndex + ITEMS_PER_PAGE);

  const handlePageChange = (page: number) => {
    setCurrentPage(page);
    window.scrollTo({ top: 0, behavior: 'smooth' });
  };

  const handleUserSelect = (iamUser: string) => {
    setUserFilter(iamUser);
    setShowUserDropdown(false);
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

  // 드롭다운에 표시할 필터링된 사용자 목록
  const filteredUserList = iamUserList.filter(
    (user) =>
      user.name.includes(userFilter) ||
      user.iamUser.toLowerCase().includes(userFilter.toLowerCase())
  );

  return (
    <div className="page">
      <div className="page-header">
        <h2>활동 로그</h2>
        <p className="page-description">AWS API 호출 이력을 확인합니다.</p>
      </div>

      <div className="filters">
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
                loadActivities();
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
          <label>이벤트</label>
          <input
            type="text"
            placeholder="예: DescribeInstances"
            value={eventFilter}
            onChange={(e) => setEventFilter(e.target.value)}
            onKeyDown={(e) => e.key === 'Enter' && loadActivities()}
            className="filter-input"
          />
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
        <button onClick={() => { loadActivities(); setShowUserDropdown(false); }} className="btn btn-primary">검색</button>
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
                <th>시간</th>
                <th>사용자</th>
                <th>서비스</th>
                <th>이벤트</th>
                <th>Source IP</th>
                <th>리전</th>
              </tr>
            </thead>
            <tbody>
              {paginatedActivities.map((activity) => (
                <tr
                  key={activity.log_id}
                  onClick={() => { setSelectedActivity(activity); document.body.classList.add('modal-open'); }}
                  style={{ cursor: 'pointer' }}
                  className={activity.error_code ? 'has-error' : ''}
                >
                  <td data-label="시간" className="date-cell">{formatDateTime(activity.event_time)}</td>
                  <td data-label="사용자">{getNameByIamUser(activity.iam_user_name)}</td>
                  <td data-label="서비스">
                    <span className="activity-service">{getServiceFromSource(activity.event_source)}</span>
                  </td>
                  <td data-label="이벤트">
                    <span className={activity.error_code ? 'text-error' : ''}>
                      {activity.event_name}
                    </span>
                    {activity.error_code && (
                      <span className="error-badge">{activity.error_code}</span>
                    )}
                  </td>
                  <td data-label="IP" className="date-cell">{activity.source_ip}</td>
                  <td data-label="리전">{activity.aws_region}</td>
                </tr>
              ))}
            </tbody>
          </table>
          {activities.length === 0 && (
            <div className="empty-state">활동 로그가 없습니다.</div>
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

      {selectedActivity && (
        <div className="modal-overlay" onClick={() => { setSelectedActivity(null); document.body.classList.remove('modal-open'); }}>
          <div className="modal" onClick={(e) => e.stopPropagation()}>
            <div className="modal-header">
              <h3>활동 상세 - {selectedActivity.event_name}</h3>
              <button className="close-btn" onClick={() => { setSelectedActivity(null); document.body.classList.remove('modal-open'); }}>×</button>
            </div>
            <div className="modal-body">
              <div className="detail-grid">
                <div className="detail-item">
                  <label>시간</label>
                  <span>{formatDateTime(selectedActivity.event_time)}</span>
                </div>
                <div className="detail-item">
                  <label>사용자</label>
                  <span>{getNameByIamUser(selectedActivity.iam_user_name)} ({selectedActivity.iam_user_name})</span>
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
                <div className="detail-item full-width">
                  <label>Role Name</label>
                  <code>{selectedActivity.role_name}</code>
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

export default ActivityList;
