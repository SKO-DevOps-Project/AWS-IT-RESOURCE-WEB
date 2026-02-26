import React, { useState, useEffect, useCallback } from 'react';
import { useNavigate } from 'react-router-dom';
import { useAuth } from '../contexts/AuthContext';
import { getTags, createTagConfig, updateTagConfig, deleteTagConfig, TagConfig } from '../api';
import Toast from '../components/Toast';
import './Pages.css';

type TabType = 'env' | 'service';

const AdminTagManagement: React.FC = () => {
  const navigate = useNavigate();
  const { user } = useAuth();
  const [activeTab, setActiveTab] = useState<TabType>('env');
  const [tags, setTags] = useState<TagConfig[]>([]);
  const [loading, setLoading] = useState(false);
  const [toast, setToast] = useState<{ message: string; type: 'success' | 'error' } | null>(null);

  // Add form state
  const [showAddForm, setShowAddForm] = useState(false);
  const [newTagValue, setNewTagValue] = useState('');
  const [newDisplayName, setNewDisplayName] = useState('');

  // Edit state
  const [editingTag, setEditingTag] = useState<string | null>(null);
  const [editTagValue, setEditTagValue] = useState('');
  const [editDisplayName, setEditDisplayName] = useState('');

  // Delete modal state
  const [deleteTarget, setDeleteTarget] = useState<TagConfig | null>(null);

  // Admin check
  useEffect(() => {
    if (user && !user.is_admin) {
      navigate('/');
    }
  }, [user, navigate]);

  const showToast = useCallback((message: string, type: 'success' | 'error') => {
    setToast({ message, type });
  }, []);

  const fetchTags = useCallback(async () => {
    setLoading(true);
    try {
      const data = await getTags(activeTab);
      setTags(data.tags || []);
    } catch (err) {
      console.error('Failed to fetch tags:', err);
      showToast('태그 목록을 불러오는데 실패했습니다', 'error');
    } finally {
      setLoading(false);
    }
  }, [activeTab, showToast]);

  useEffect(() => {
    fetchTags();
  }, [fetchTags]);

  const handleTabChange = (tab: TabType) => {
    setActiveTab(tab);
    setShowAddForm(false);
    setEditingTag(null);
  };

  const handleAdd = async () => {
    if (!newTagValue.trim()) {
      showToast('값을 입력해주세요', 'error');
      return;
    }

    try {
      // sort_order: 기존 태그 수 기반으로 자동 부여
      const nextOrder = (tags.length + 1) * 10;
      await createTagConfig({
        tag_type: activeTab,
        tag_value: newTagValue.trim(),
        display_name: newDisplayName.trim() || newTagValue.trim(),
        sort_order: nextOrder,
      });
      showToast('태그가 추가되었습니다', 'success');
      setShowAddForm(false);
      setNewTagValue('');
      setNewDisplayName('');
      fetchTags();
    } catch (err: any) {
      const msg = err?.response?.data?.error || '태그 추가에 실패했습니다';
      showToast(msg, 'error');
    }
  };

  const handleStartEdit = (tag: TagConfig) => {
    setEditingTag(tag.tag_value);
    setEditTagValue(tag.tag_value);
    setEditDisplayName(tag.display_name || '');
  };

  const handleSaveEdit = async (tag: TagConfig) => {
    if (!editTagValue.trim()) {
      showToast('값을 입력해주세요', 'error');
      return;
    }
    try {
      await updateTagConfig(tag.tag_type, tag.tag_value, {
        display_name: editDisplayName || undefined,
        new_tag_value: editTagValue.trim() !== tag.tag_value ? editTagValue.trim() : undefined,
      });
      showToast('태그가 수정되었습니다', 'success');
      setEditingTag(null);
      fetchTags();
    } catch (err) {
      console.error('Failed to update tag:', err);
      showToast('태그 수정에 실패했습니다', 'error');
    }
  };

  const handleDelete = async () => {
    if (!deleteTarget) return;

    try {
      await deleteTagConfig(deleteTarget.tag_type, deleteTarget.tag_value);
      showToast('태그가 삭제되었습니다', 'success');
      setDeleteTarget(null);
      fetchTags();
    } catch (err) {
      console.error('Failed to delete tag:', err);
      showToast('태그 삭제에 실패했습니다', 'error');
    }
  };

  if (!user?.is_admin) return null;

  return (
    <div className="page">
      <div className="page-header">
        <h2>태그 설정</h2>
        <p className="page-description">Environment / Service 태그 값을 관리합니다</p>
      </div>

      {/* Tabs */}
      <div className="tag-tabs">
        <button
          className={`tag-tab ${activeTab === 'env' ? 'active' : ''}`}
          onClick={() => handleTabChange('env')}
        >
          Environment
        </button>
        <button
          className={`tag-tab ${activeTab === 'service' ? 'active' : ''}`}
          onClick={() => handleTabChange('service')}
        >
          Service
        </button>
      </div>

      {/* Add button / form */}
      <div style={{ marginBottom: 16 }}>
        {!showAddForm ? (
          <button className="btn btn-primary" onClick={() => setShowAddForm(true)}>
            + 추가
          </button>
        ) : (
          <div className="tag-add-form">
            <div className="tag-add-form-fields">
              <input
                type="text"
                placeholder={activeTab === 'env' ? '값 (예: prod, dev)' : '값 (예: aihub, safety)'}
                value={newTagValue}
                onChange={e => setNewTagValue(e.target.value)}
                className="tag-input"
              />
              {activeTab === 'service' && (
                <input
                  type="text"
                  placeholder="표시명 (예: ai-hub)"
                  value={newDisplayName}
                  onChange={e => setNewDisplayName(e.target.value)}
                  className="tag-input"
                />
              )}
            </div>
            <div className="tag-add-form-actions">
              <button className="btn btn-primary" onClick={handleAdd}>저장</button>
              <button className="btn btn-secondary" onClick={() => { setShowAddForm(false); setNewTagValue(''); setNewDisplayName(''); }}>취소</button>
            </div>
          </div>
        )}
      </div>

      {/* Table */}
      {loading ? (
        <div className="loading-container">
          <div className="loading-spinner"></div>
          <p>불러오는 중...</p>
        </div>
      ) : (
        <table className="data-table">
          <thead>
            <tr>
              <th style={{ width: 60 }}>#</th>
              <th>값</th>
              {activeTab === 'service' && <th>표시명</th>}
              <th style={{ width: 160 }}>등록일</th>
              <th style={{ width: 160 }}>작업</th>
            </tr>
          </thead>
          <tbody>
            {tags.length === 0 ? (
              <tr>
                <td colSpan={activeTab === 'service' ? 5 : 4} style={{ textAlign: 'center', padding: 32, color: '#9ca3af' }}>
                  등록된 태그가 없습니다
                </td>
              </tr>
            ) : (
              tags.map((tag, index) => (
                <tr key={tag.tag_value}>
                  <td style={{ color: '#9ca3af' }}>{index + 1}</td>
                  <td>
                    {editingTag === tag.tag_value ? (
                      <input
                        type="text"
                        value={editTagValue}
                        onChange={e => setEditTagValue(e.target.value)}
                        className="tag-input"
                      />
                    ) : (
                      <code>{tag.tag_value}</code>
                    )}
                  </td>
                  {activeTab === 'service' && (
                    <td>
                      {editingTag === tag.tag_value ? (
                        <input
                          type="text"
                          value={editDisplayName}
                          onChange={e => setEditDisplayName(e.target.value)}
                          className="tag-input"
                        />
                      ) : (
                        tag.display_name || '-'
                      )}
                    </td>
                  )}
                  <td>{tag.created_at ? new Date(tag.created_at).toLocaleDateString('ko-KR') : '-'}</td>
                  <td>
                    {editingTag === tag.tag_value ? (
                      <div className="action-buttons">
                        <button className="action-btn-approve" onClick={() => handleSaveEdit(tag)}>저장</button>
                        <button className="action-btn-revoke" onClick={() => setEditingTag(null)}>취소</button>
                      </div>
                    ) : (
                      <div className="action-buttons">
                        <button className="action-btn action-btn-edit" onClick={() => handleStartEdit(tag)}>수정</button>
                        <button className="action-btn action-btn-delete" onClick={() => setDeleteTarget(tag)}>삭제</button>
                      </div>
                    )}
                  </td>
                </tr>
              ))
            )}
          </tbody>
        </table>
      )}

      {/* Delete confirmation modal */}
      {deleteTarget && (
        <div className="modal-overlay" onClick={() => setDeleteTarget(null)}>
          <div className="modal" style={{ maxWidth: 420 }} onClick={e => e.stopPropagation()}>
            <div className="modal-header">
              <h3>태그 삭제</h3>
              <button className="close-btn" onClick={() => setDeleteTarget(null)}>&times;</button>
            </div>
            <div className="modal-body">
              <p style={{ margin: '0 0 24px', color: '#6b7280' }}>
                <strong>{deleteTarget.tag_value}</strong> 태그를 삭제하시겠습니까?
              </p>
              <div style={{ display: 'flex', gap: 8, justifyContent: 'flex-end' }}>
                <button className="btn btn-secondary" onClick={() => setDeleteTarget(null)}>취소</button>
                <button className="btn btn-danger" onClick={handleDelete}>삭제</button>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Toast */}
      {toast && (
        <Toast
          message={toast.message}
          type={toast.type}
          onClose={() => setToast(null)}
        />
      )}
    </div>
  );
};

export default AdminTagManagement;
