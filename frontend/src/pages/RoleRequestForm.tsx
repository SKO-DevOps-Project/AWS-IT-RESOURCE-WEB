import React, { useState, useEffect } from 'react';
import { useNavigate, useSearchParams } from 'react-router-dom';
import { useAuth } from '../contexts/AuthContext';
import {
  getRoleRequestOptions,
  createRoleRequest,
  RoleRequestOptionsResponse,
  RoleRequestFormData,
} from '../api';
import Toast from '../components/Toast';
import './Pages.css';

// Calculate default end time (now + 1 hour, KST)
const getDefaultEndTime = () => {
  const now = new Date();
  const endTime = new Date(now.getTime() + 60 * 60 * 1000); // +1 hour
  const year = endTime.getFullYear();
  const month = String(endTime.getMonth() + 1).padStart(2, '0');
  const day = String(endTime.getDate()).padStart(2, '0');
  const hours = String(endTime.getHours()).padStart(2, '0');
  const minutes = String(endTime.getMinutes()).padStart(2, '0');
  return `${year}-${month}-${day}T${hours}:${minutes}`;
};

const RoleRequestForm: React.FC = () => {
  const navigate = useNavigate();
  const [searchParams] = useSearchParams();
  const { user } = useAuth();
  const [loading, setLoading] = useState(true);
  const [submitting, setSubmitting] = useState(false);
  const [options, setOptions] = useState<RoleRequestOptionsResponse | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [toast, setToast] = useState<{ message: string; type: 'success' | 'error' } | null>(null);

  // Form state - end_time에 기본값 설정
  const [formData, setFormData] = useState<RoleRequestFormData>({
    iam_user_name: '',
    env: '',
    service: '',
    permission_type: 'read_update',
    target_services: 'all',
    start_time: '',
    end_time: getDefaultEndTime(),
    purpose: '',
    work_request_id: '',
  });

  useEffect(() => {
    loadOptions();
  }, []);

  useEffect(() => {
    // Pre-fill work_request_id from URL params
    const workRequestId = searchParams.get('work_request_id');
    if (workRequestId) {
      setFormData(prev => ({ ...prev, work_request_id: workRequestId }));
    }
  }, [searchParams]);

  const loadOptions = async () => {
    try {
      setLoading(true);
      const data = await getRoleRequestOptions();
      setOptions(data);

      // Set default values
      if (data.envs.length > 0) {
        setFormData(prev => ({
          ...prev,
          env: prev.env || '',
          service: prev.service || '',
        }));
      }
    } catch (err: any) {
      setError(err.response?.data?.error || '옵션 로딩 중 오류가 발생했습니다');
    } finally {
      setLoading(false);
    }
  };

  const handleChange = (e: React.ChangeEvent<HTMLInputElement | HTMLSelectElement | HTMLTextAreaElement>) => {
    const { name, value } = e.target;
    setFormData(prev => ({ ...prev, [name]: value }));
    setError(null);
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);

    // Validation
    if (!formData.iam_user_name) {
      setError('IAM User명을 선택해주세요');
      return;
    }
    if (!formData.env) {
      setError('Environment를 선택해주세요');
      return;
    }
    if (!formData.service) {
      setError('Service를 선택해주세요');
      return;
    }
    if (!formData.end_time) {
      setError('종료 시간을 입력해주세요');
      return;
    }
    if (!formData.purpose.trim()) {
      setError('목적을 입력해주세요');
      return;
    }

    try {
      setSubmitting(true);

      // Prepare data
      const submitData: RoleRequestFormData = {
        ...formData,
        purpose: formData.purpose.trim(),
      };

      // Remove empty optional fields
      if (!submitData.iam_user_name) delete submitData.iam_user_name;
      if (!submitData.start_time) delete submitData.start_time;
      if (!submitData.work_request_id) delete submitData.work_request_id;

      await createRoleRequest(submitData);
      setToast({ message: '권한 요청이 제출되었습니다', type: 'success' });

      // Redirect to role-requests list after 2 seconds
      setTimeout(() => {
        navigate('/role-requests');
      }, 2000);
    } catch (err: any) {
      setToast({ message: err.response?.data?.error || '요청 제출 중 오류가 발생했습니다', type: 'error' });
    } finally {
      setSubmitting(false);
    }
  };

  if (loading) {
    return (
      <div className="page">
        <div className="loading">로딩 중...</div>
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
        <h2>AWS 권한 요청</h2>
        <p className="page-description">AWS 리소스 접근 권한을 요청합니다. 승인 후 알림을 받습니다.</p>
      </div>

      <div className="form-card">
        <form onSubmit={handleSubmit} className="form-content">
          {error && <div className="form-error">{error}</div>}

          {/* 요청자 정보 */}
          <div className="form-section">
            <h3 className="form-section-title">요청자 정보</h3>
            <div className="form-row">
              <div className="form-group">
                <label htmlFor="iam_user_name">IAM User *</label>
                <select
                  id="iam_user_name"
                  name="iam_user_name"
                  value={formData.iam_user_name}
                  onChange={handleChange}
                  className="form-select"
                  required
                >
                  <option value="">선택하세요</option>
                  {options?.users.map(u => (
                    <option key={u.user_id} value={u.iam_user_name}>
                      {u.name} ({u.iam_user_name})
                    </option>
                  ))}
                </select>
              </div>

              <div className="form-group">
                <label htmlFor="work_request_id">연관 업무 요청</label>
                <select
                  id="work_request_id"
                  name="work_request_id"
                  value={formData.work_request_id}
                  onChange={handleChange}
                  className="form-select"
                >
                  <option value="">선택 안함</option>
                  {options?.work_requests.map(wr => (
                    <option key={wr.value} value={wr.value}>{wr.label}</option>
                  ))}
                </select>
              </div>
            </div>
          </div>

          {/* 권한 설정 */}
          <div className="form-section">
            <h3 className="form-section-title">권한 설정</h3>
            <div className="form-row">
              <div className="form-group">
                <label htmlFor="env">Environment *</label>
                <select
                  id="env"
                  name="env"
                  value={formData.env}
                  onChange={handleChange}
                  className="form-select"
                  required
                >
                  <option value="">선택하세요</option>
                  {options?.envs.map(opt => (
                    <option key={opt.value} value={opt.value}>{opt.label}</option>
                  ))}
                </select>
              </div>

              <div className="form-group">
                <label htmlFor="service">Service *</label>
                <select
                  id="service"
                  name="service"
                  value={formData.service}
                  onChange={handleChange}
                  className="form-select"
                  required
                >
                  <option value="">선택하세요</option>
                  {options?.services.map(opt => (
                    <option key={opt.value} value={opt.value}>{opt.label}</option>
                  ))}
                </select>
              </div>
            </div>

            <div className="form-row" style={{ marginTop: '16px' }}>
              <div className="form-group">
                <label htmlFor="permission_type">권한 유형 *</label>
                <select
                  id="permission_type"
                  name="permission_type"
                  value={formData.permission_type}
                  onChange={handleChange}
                  className="form-select"
                  required
                >
                  {options?.permission_types.map(opt => (
                    <option key={opt.value} value={opt.value}>{opt.label}</option>
                  ))}
                </select>
              </div>

              <div className="form-group">
                <label htmlFor="target_services">대상 AWS 서비스 *</label>
                <select
                  id="target_services"
                  name="target_services"
                  value={formData.target_services}
                  onChange={handleChange}
                  className="form-select"
                  required
                >
                  {options?.target_services.map(opt => (
                    <option key={opt.value} value={opt.value}>{opt.label}</option>
                  ))}
                </select>
              </div>
            </div>
          </div>

          {/* 시간 설정 */}
          <div className="form-section">
            <h3 className="form-section-title">시간 설정</h3>
            <div className="form-row">
              <div className="form-group">
                <label htmlFor="start_time">시작 시간</label>
                <input
                  type="datetime-local"
                  id="start_time"
                  name="start_time"
                  value={formData.start_time}
                  onChange={handleChange}
                  className="form-input"
                />
                <span className="form-hint">비워두면 즉시 시작</span>
              </div>

              <div className="form-group">
                <label htmlFor="end_time">종료 시간 *</label>
                <input
                  type="datetime-local"
                  id="end_time"
                  name="end_time"
                  value={formData.end_time}
                  onChange={handleChange}
                  className="form-input"
                  required
                />
              </div>
            </div>
          </div>

          {/* 요청 사유 */}
          <div className="form-section">
            <h3 className="form-section-title">요청 사유</h3>
            <div className="form-group">
              <label htmlFor="purpose">목적 *</label>
              <textarea
                id="purpose"
                name="purpose"
                value={formData.purpose}
                onChange={handleChange}
                placeholder="권한이 필요한 이유를 상세히 작성해주세요"
                className="form-textarea"
                rows={4}
                required
              />
            </div>
          </div>

          <div className="form-actions">
            <button
              type="button"
              className="btn btn-secondary"
              onClick={() => navigate(-1)}
              disabled={submitting}
            >
              취소
            </button>
            <button
              type="submit"
              className="btn btn-primary"
              disabled={submitting}
            >
              {submitting ? '요청 중...' : '권한 요청'}
            </button>
          </div>
        </form>
      </div>
    </div>
  );
};

export default RoleRequestForm;
