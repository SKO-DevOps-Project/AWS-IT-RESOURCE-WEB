import React, { useState, useEffect } from 'react';
import { NavLink, useNavigate, useLocation } from 'react-router-dom';
import { useAuth } from '../contexts/AuthContext';
import './Sidebar.css';

const Sidebar: React.FC = () => {
  const navigate = useNavigate();
  const location = useLocation();
  const { user, logout } = useAuth();
  const [isOpen, setIsOpen] = useState(false);

  // 페이지 이동 시 사이드바 닫기
  useEffect(() => {
    setIsOpen(false);
  }, [location.pathname]);

  const handleHeaderClick = () => {
    navigate('/');
    setIsOpen(false);
  };

  const handleLogout = () => {
    logout();
    navigate('/login');
  };

  const toggleSidebar = () => {
    setIsOpen(!isOpen);
  };

  return (
    <>
      {/* 햄버거 메뉴 버튼 */}
      <button className="hamburger-btn" onClick={toggleSidebar}>
        <span className={`hamburger-icon ${isOpen ? 'open' : ''}`}>
          <span></span>
          <span></span>
          <span></span>
        </span>
      </button>

      {/* 오버레이 */}
      {isOpen && <div className="sidebar-overlay" onClick={() => setIsOpen(false)} />}

      <aside className={`sidebar ${isOpen ? 'open' : ''}`}>
      <div className="sidebar-header" onClick={handleHeaderClick}>
        <img src="/sk_logo.png" alt="SK Logo" className="sidebar-logo" />
        <h1>서버 접근통제 시스템</h1>
      </div>
      <nav className="sidebar-nav">
        <NavLink to="/" className={({ isActive }) => isActive ? 'nav-item active' : 'nav-item'} end>
          <span className="nav-text">대시보드</span>
        </NavLink>
        <NavLink to="/work-requests" className={({ isActive }) => isActive ? 'nav-item active' : 'nav-item'}>
          <span className="nav-text">업무 요청</span>
        </NavLink>
        <NavLink to="/role-requests" className={({ isActive }) => isActive ? 'nav-item active' : 'nav-item'}>
          <span className="nav-text">업무 권한 요청</span>
        </NavLink>
        <NavLink to="/activities" className={({ isActive }) => isActive ? 'nav-item active' : 'nav-item'}>
          <span className="nav-text">활동 로그</span>
        </NavLink>
      </nav>
      <div className="sidebar-user">
        {user && (
          <>
            <div className="user-info">
              <div className="user-name">{user.name}</div>
              <div className="user-detail">{user.team}</div>
              {user.is_admin && <span className="admin-badge">관리자</span>}
            </div>
            <button className="logout-btn" onClick={handleLogout}>
              로그아웃
            </button>
          </>
        )}
      </div>
      <div className="sidebar-footer">
        <span>v1.0.0</span>
      </div>
    </aside>
    </>
  );
};

export default Sidebar;
