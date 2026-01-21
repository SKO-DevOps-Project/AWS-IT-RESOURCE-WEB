import React from 'react';
import { NavLink, useNavigate } from 'react-router-dom';
import { useAuth } from '../contexts/AuthContext';
import './Sidebar.css';

const Sidebar: React.FC = () => {
  const navigate = useNavigate();
  const { user, logout } = useAuth();

  const handleHeaderClick = () => {
    navigate('/');
  };

  const handleLogout = () => {
    logout();
    navigate('/login');
  };

  return (
    <aside className="sidebar">
      <div className="sidebar-header" onClick={handleHeaderClick}>
        <img src="/sk_logo.png" alt="SK Logo" className="sidebar-logo" />
        <h1>서버 접근통제 시스템</h1>
      </div>
      <nav className="sidebar-nav">
        <NavLink to="/" className={({ isActive }) => isActive ? 'nav-item active' : 'nav-item'} end>
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
  );
};

export default Sidebar;
