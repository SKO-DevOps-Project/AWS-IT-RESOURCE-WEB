import React, { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { useAuth } from '../contexts/AuthContext';
import {
  getRoleRequestOptions,
  createAdminRoleGrant,
  RoleRequestOptionsResponse,
  AdminRoleGrantFormData,
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

const AdminRoleGrantForm: React.FC = () => {
  const navigate = useNavigate();
  const { user } = useAuth();
  const [loading, setLoading] = useState(true);
  const [submitting, setSubmitting] = useState(false);
  const [options, setOptions] = useState<RoleRequestOptionsResponse | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [toast, setToast] = useState<{ message: string; type: 'success' | 'error' } | null>(null);
  const [result, setResult] = useState<{ role_arn?: string; role_name?: string } | null>(null);

  // Form state - end_time에 기본값 설정
  const [formData, setFormData] = useState<AdminRoleGrantFormData>({
    target_user_id: '',
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
    // Check admin permission
    if (user && !user.is_admin) {
      navigate('/');
      return;
    }
    loadOptions();
  }, [user, navigate]);

  const loadOptions = async () => {
    try {
      setLoading(true);
      const data = await getRoleRequestOptions();
      setOptions(data);
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

    // Auto-fill IAM user name when target user is selected
    if (name === 'target_user_id') {
      const selectedUser = options?.users.find(u => u.user_id === value);
      if (selectedUser?.iam_user_name) {
        setFormData(prev => ({
          ...prev,
          [name]: value,
          iam_user_name: selectedUser.iam_user_name,
        }));
      }
    }
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);
    setResult(null);

    // Validation
    if (!formData.target_user_id) {
      setError('대상 사용자를 선택해주세요');
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

    // Confirm before submitting
    const selectedUser = options?.users.find(u => u.user_id === formData.target_user_id);
    const confirmed = window.confirm(
      `${selectedUser?.name || formData.target_user_id}님에게 AWS 권한을 즉시 부여합니다.\n계속하시겠습니까?`
    );
    if (!confirmed) return;

    try {
      setSubmitting(true);

      // Prepare data
      const submitData: AdminRoleGrantFormData = {
        ...formData,
        purpose: formData.purpose.trim(),
      };

      // Remove empty optional fields
      if (!submitData.iam_user_name) delete submitData.iam_user_name;
      if (!submitData.start_time) delete submitData.start_time;
      if (!submitData.work_request_id) delete submitData.work_request_id;

      const responseData = await createAdminRoleGrant(submitData);
      setToast({ message: 'AWS Role이 즉시 생성되었습니다', type: 'success' });
      setResult({
        role_arn: responseData.role_arn,
        role_name: responseData.role_name,
      });
    } catch (err: any) {
      setToast({ message: err.response?.data?.error || '권한 부여 중 오류가 발생했습니다', type: 'error' });
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
        <h2>AWS 권한 즉시 부여 <span className="admin-badge-inline">Admin</span></h2>
        <p className="page-description">지정한 사용자에게 AWS 권한을 즉시 부여합니다.</p>
      </div>

      <div className="form-card">
        <form onSubmit={handleSubmit} className="form-content">
          {error && <div className="form-error">{error}</div>}

          {/* 대상 사용자 */}
          <div className="form-section">
            <h3 className="form-section-title">대상 사용자</h3>
            <div className="form-row">
              <div className="form-group">
                <label htmlFor="target_user_id">사용자 선택 *</label>
                <select
                  id="target_user_id"
                  name="target_user_id"
                  value={formData.target_user_id}
                  onChange={handleChange}
                  className="form-select"
                  required
                  disabled={!!result}
                >
                  <option value="">선택하세요</option>
                  {options?.users.map(u => (
                    <option key={u.user_id} value={u.user_id}>
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
                  disabled={!!result}
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
                  disabled={!!result}
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
                  disabled={!!result}
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
                  disabled={!!result}
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
                  disabled={!!result}
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
                  disabled={!!result}
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
                  disabled={!!result}
                />
              </div>
            </div>
          </div>

          {/* 부여 사유 */}
          <div className="form-section">
            <h3 className="form-section-title">부여 사유</h3>
            <div className="form-group">
              <label htmlFor="purpose">목적 *</label>
              <textarea
                id="purpose"
                name="purpose"
                value={formData.purpose}
                onChange={handleChange}
                placeholder="권한 부여 사유를 작성해주세요"
                className="form-textarea"
                rows={4}
                required
                disabled={!!result}
              />
            </div>
          </div>

          {/* 결과 표시 (버튼 위) */}
          {result?.role_arn && (
            <div className="result-section">
              <div className="result-success">
                <h4>Role이 생성되었습니다</h4>
                <div className="result-info">
                  <label>Role ARN:</label>
                  <code>{result.role_arn}</code>
                </div>
              </div>
            </div>
          )}

          <div className="form-actions">
            {result ? (
              <>
                <button
                  type="button"
                  className="btn btn-secondary"
                  onClick={() => navigate('/role-requests')}
                >
                  목록으로
                </button>
                <button
                  type="button"
                  className="btn btn-primary"
                  onClick={() => {
                    setResult(null);
                    setFormData({
                      target_user_id: '',
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
                  }}
                >
                  새 권한 부여
                </button>
              </>
            ) : (
              <>
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
                  {submitting ? '생성 중...' : '즉시 권한 부여'}
                </button>
              </>
            )}
          </div>
        </form>
      </div>
    </div>
  );
};

export default AdminRoleGrantForm;
