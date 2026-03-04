import React, { useState, useEffect } from 'react';
import changelog, { CURRENT_VERSION } from '../data/changelog';
import './WhatsNew.css';

const BADGE_LABELS: Record<string, string> = {
  new: '신규',
  improved: '개선',
  fixed: '수정',
};

const WhatsNew: React.FC = () => {
  const [isOpen, setIsOpen] = useState(false);

  // 자동 팝업 로직
  useEffect(() => {
    const latest = changelog[0];
    if (!latest) return;

    const today = new Date().toISOString().slice(0, 10);

    // 1) showUntil 만료 확인
    if (latest.showUntil < today) return;

    // 2) "오늘 하루 보지 않기" 확인
    const dismissDate = localStorage.getItem('whats_new_dismiss_date');
    if (dismissDate === today) return;

    // 3) 이미 이 버전 확인했는지
    const seenVersion = localStorage.getItem('whats_new_seen_version');
    if (seenVersion === CURRENT_VERSION) return;

    // 위 조건 모두 통과 → 자동 오픈
    setIsOpen(true);
  }, []);

  // 사이드바 버튼으로 수동 열기
  useEffect(() => {
    const handler = () => setIsOpen(true);
    window.addEventListener('open-whats-new', handler);
    return () => window.removeEventListener('open-whats-new', handler);
  }, []);

  const handleClose = () => {
    localStorage.setItem('whats_new_seen_version', CURRENT_VERSION);
    setIsOpen(false);
  };

  const handleDismissToday = () => {
    const today = new Date().toISOString().slice(0, 10);
    localStorage.setItem('whats_new_dismiss_date', today);
    setIsOpen(false);
  };

  if (!isOpen) return null;

  return (
    <div className="modal-overlay" onClick={handleClose}>
      <div className="modal whats-new-modal" onClick={(e) => e.stopPropagation()}>
        <div className="modal-header">
          <h3>What's New</h3>
          <button className="close-btn" onClick={handleClose}>
            &times;
          </button>
        </div>
        <div className="modal-body">
          {changelog.map((entry) => (
            <div key={entry.version} className="whats-new-version">
              <div className="whats-new-version-header">
                <span className="whats-new-version-tag">v{entry.version}</span>
                <span className="whats-new-version-date">{entry.date}</span>
              </div>
              <p className="whats-new-version-title">{entry.title}</p>
              <ul className="whats-new-items">
                {entry.items.map((item, idx) => (
                  <li key={idx} className="whats-new-item">
                    <span className={`whats-new-badge badge-${item.type}`}>
                      {BADGE_LABELS[item.type]}
                    </span>
                    <span>{item.text}</span>
                  </li>
                ))}
              </ul>
            </div>
          ))}
        </div>
        <div className="whats-new-footer">
          <button className="whats-new-dismiss-btn" onClick={handleDismissToday}>
            오늘 하루 보지 않기
          </button>
          <button className="whats-new-close-btn" onClick={handleClose}>
            닫기
          </button>
        </div>
      </div>
    </div>
  );
};

export default WhatsNew;
