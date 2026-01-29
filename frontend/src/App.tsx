import React from 'react';
import { BrowserRouter as Router, Routes, Route } from 'react-router-dom';
import { AuthProvider } from './contexts/AuthContext';
import ProtectedRoute from './components/ProtectedRoute';
import Sidebar from './components/Sidebar';
import LoginPage from './pages/LoginPage';
import Dashboard from './pages/Dashboard';
import WorkRequestList from './pages/WorkRequestList';
import TicketList from './pages/TicketList';
import TicketDetail from './pages/TicketDetail';
import ActivityList from './pages/ActivityList';
import RoleRequestForm from './pages/RoleRequestForm';
import AdminRoleGrantForm from './pages/AdminRoleGrantForm';
import AdminTicketApproval from './pages/AdminTicketApproval';
import './App.css';

function App() {
  return (
    <AuthProvider>
      <Router>
        <Routes>
          <Route path="/login" element={<LoginPage />} />
          <Route
            path="/*"
            element={
              <ProtectedRoute>
                <div className="app">
                  <Sidebar />
                  <main className="main-content">
                    <Routes>
                      <Route path="/" element={<Dashboard />} />
                      <Route path="/work-requests" element={<WorkRequestList />} />
                      <Route path="/role-requests" element={<TicketList />} />
                      <Route path="/role-requests/new" element={<RoleRequestForm />} />
                      <Route path="/admin/role-grant" element={<AdminRoleGrantForm />} />
                      <Route path="/admin/approval" element={<AdminTicketApproval />} />
                      <Route path="/tickets/:requestId" element={<TicketDetail />} />
                      <Route path="/activities" element={<ActivityList />} />
                    </Routes>
                  </main>
                </div>
              </ProtectedRoute>
            }
          />
        </Routes>
      </Router>
    </AuthProvider>
  );
}

export default App;
