import React, { useState, useEffect } from 'react';
import { BrowserRouter, Routes, Route, Navigate, Outlet } from 'react-router-dom';
import { AuthProvider } from './contexts/AuthContext';
import ProtectedRoute from './components/ProtectedRoute';
import Sidebar from './components/Sidebar';
import Login from './pages/Login';
import Signup from './pages/Signup';
import ForgotPassword from './pages/ForgotPassword';
import Dashboard from './pages/Dashboard';
import AdminPanel from './pages/AdminPanel';
import ThreatMonitor from './pages/ThreatMonitor';
import Unauthorized from './pages/Unauthorized';
import Suspended from './pages/Suspended';

// Layout structure for authenticated users containing Sidebar + Viewport
const DashboardLayout: React.FC = () => {
  return (
    <div className="app-container">
      <Sidebar />
      <main className="main-content">
        <Outlet />
      </main>
    </div>
  );
};

export const App: React.FC = () => {
  const [emailNotification, setEmailNotification] = useState<any | null>(null);

  useEffect(() => {
    const handleEmail = (e: Event) => {
      const customEvent = e as CustomEvent;
      setEmailNotification(customEvent.detail);
      
      // Auto-dismiss notification after 8 seconds
      const timer = setTimeout(() => {
        setEmailNotification(null);
      }, 8000);
      return () => clearTimeout(timer);
    };

    window.addEventListener('security-email-sent', handleEmail);
    return () => window.removeEventListener('security-email-sent', handleEmail);
  }, []);

  return (
    <AuthProvider>
      <BrowserRouter>
        <Routes>
          {/* Public Auth Routes */}
          <Route path="/login" element={<Login />} />
          <Route path="/signup" element={<Signup />} />
          <Route path="/forgot-password" element={<ForgotPassword />} />
          <Route path="/unauthorized" element={<Unauthorized />} />
          <Route path="/suspended" element={<Suspended />} />

          {/* Protected General Operator Routes */}
          <Route element={<ProtectedRoute />}>
            <Route element={<DashboardLayout />}>
              <Route path="/dashboard" element={<Dashboard />} />
              <Route path="/threats" element={<ThreatMonitor />} />
              
              {/* Protected Admin-Only Routes */}
              <Route element={<ProtectedRoute requiredRole="Admin" />}>
                <Route path="/admin" element={<AdminPanel />} />
              </Route>
            </Route>
          </Route>

          {/* Catch-all Fallbacks */}
          <Route path="/" element={<Navigate to="/dashboard" replace />} />
          <Route path="*" element={<Navigate to="/dashboard" replace />} />
        </Routes>
      </BrowserRouter>

      {/* Styled Simulated SMTP Email Outbox Toaster */}
      {emailNotification && (
        <div style={{
          position: 'fixed',
          bottom: '24px',
          right: '24px',
          zIndex: 99999,
          width: '360px',
          backgroundColor: 'var(--bg-secondary)',
          borderLeft: `4px solid ${
            emailNotification.severity === 'Critical' ? 'var(--danger)' :
            emailNotification.severity === 'High' ? '#f97316' :
            emailNotification.severity === 'Medium' ? 'var(--warning)' : 'var(--success)'
          }`,
          boxShadow: '0 20px 25px -5px rgba(0, 0, 0, 0.4), 0 10px 10px -5px rgba(0, 0, 0, 0.3)',
          borderRadius: '8px',
          padding: '16px',
          border: '1px solid var(--border-color)',
          fontFamily: 'inherit',
          animation: 'slideIn 0.35s cubic-bezier(0.16, 1, 0.3, 1)'
        }}>
          <style>{`
            @keyframes slideIn {
              from { transform: translateY(20px); opacity: 0; }
              to { transform: translateY(0); opacity: 1; }
            }
          `}</style>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '8px' }}>
            <span style={{ fontSize: '0.72rem', fontWeight: 800, color: 'var(--primary)', letterSpacing: '0.08em' }}>
              📧 SMTP SECURITY ALERT DISPATCHED
            </span>
            <button
              onClick={() => setEmailNotification(null)}
              style={{ background: 'none', border: 'none', color: 'var(--text-secondary)', cursor: 'pointer', fontSize: '1.2rem', padding: '0 4px', lineVerticalAlign: 'middle' }}
            >
              ×
            </button>
          </div>
          <div style={{ fontSize: '0.85rem', fontWeight: 700, color: 'var(--text-primary)', marginBottom: '4px' }}>
            To: <span style={{ color: 'var(--primary)' }}>{emailNotification.to}</span>
          </div>
          <div style={{ fontSize: '0.78rem', color: 'var(--text-muted)', marginBottom: '10px' }}>
            Subject: {emailNotification.subject}
          </div>
          <div style={{
            fontSize: '0.74rem',
            backgroundColor: 'var(--bg-primary)',
            border: '1px solid var(--border-color)',
            borderRadius: '6px',
            padding: '10px',
            fontFamily: 'var(--font-mono)',
            maxHeight: '120px',
            overflowY: 'auto',
            whiteSpace: 'pre-wrap',
            color: 'var(--text-secondary)',
            lineHeight: 1.5
          }}>
            {emailNotification.body}
          </div>
        </div>
      )}
    </AuthProvider>
  );
};

export default App;

