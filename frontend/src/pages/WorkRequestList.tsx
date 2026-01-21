import React, { useEffect, useState } from 'react';
import { getWorkRequests, updateWorkRequestStatus, WorkRequest } from '../api';
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

const WorkRequestList: React.FC = () => {
  const [workRequests, setWorkRequests] = useState<WorkRequest[]>([]);
  const [loading, setLoading] = useState(true);
  const [serviceFilter, setServiceFilter] = useState<string>('');
  const [statusFilter, setStatusFilter] = useState<string>('');
  const [selectedRequest, setSelectedRequest] = useState<WorkRequest | null>(null);
  const [updating, setUpdating] = useState(false);

  useEffect(() => {
    loadWorkRequests();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

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
                  onClick={() => setSelectedRequest(request)}
                  style={{ cursor: 'pointer' }}
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
        <div className="modal-overlay" onClick={() => setSelectedRequest(null)}>
          <div className="modal" onClick={(e) => e.stopPropagation()}>
            <div className="modal-header">
              <h3>업무 요청 상세</h3>
              <button className="close-btn" onClick={() => setSelectedRequest(null)}>×</button>
            </div>
            <div className="modal-body">
              <div className="detail-grid">
                <div className="detail-item">
                  <label>상태</label>
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
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

export default WorkRequestList;
