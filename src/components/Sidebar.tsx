import React, { useState, useEffect } from 'react';
import { NavLink, useNavigate } from 'react-router-dom';
import { 
  Shield, 
  LayoutDashboard, 
  LogOut, 
  Sun, 
  Moon, 
  ChevronLeft, 
  ChevronRight,
  ShieldCheck,
  ShieldAlert
} from 'lucide-react';
import { useAuth } from '../contexts/AuthContext';

export const Sidebar: React.FC = () => {
  const { user, role, signOut } = useAuth();
  const navigate = useNavigate();
  const [isCollapsed, setIsCollapsed] = useState(false);
  const [theme, setTheme] = useState<'light' | 'dark'>(() => {
    return (localStorage.getItem('cybershield-theme') as 'light' | 'dark') || 'dark';
  });
  useEffect(() => {
    document.documentElement.setAttribute('data-theme', theme);
    localStorage.setItem('cybershield-theme', theme);
  }, [theme]);


  const toggleTheme = () => setTheme(prev => prev === 'light' ? 'dark' : 'light');

  const handleLogout = async () => {
    await signOut();
    navigate('/login');
  };

  const userInitial = user?.email ? user.email.charAt(0).toUpperCase() : '?';

  return (
    <aside className={`sidebar ${isCollapsed ? 'collapsed' : ''}`}>
      <div className="sidebar-header">
        <div className="sidebar-logo-group">
          <Shield className="sidebar-logo" />
          <span className="sidebar-title">CyberShield AI</span>
        </div>
        <button 
          className="sidebar-toggle-btn" 
          onClick={() => setIsCollapsed(!isCollapsed)}
          title={isCollapsed ? 'Expand Sidebar' : 'Collapse Sidebar'}
        >
          {isCollapsed ? <ChevronRight size={18} /> : <ChevronLeft size={18} />}
        </button>
      </div>

      <nav className="sidebar-nav">
        {/* Dashboard */}
        <NavLink 
          to="/dashboard" 
          className={({ isActive }) => `sidebar-nav-item ${isActive ? 'active' : ''}`}
        >
          <LayoutDashboard className="sidebar-nav-icon" />
          <span className="sidebar-nav-label">Dashboard</span>
        </NavLink>


        {/* Threat Monitor */}
        <NavLink 
          to="/threats" 
          className={({ isActive }) => `sidebar-nav-item ${isActive ? 'active' : ''}`}
        >
          <ShieldAlert className="sidebar-nav-icon" />
          <span className="sidebar-nav-label">Threat Monitor</span>
        </NavLink>

        {/* Admin Control (admin only) */}
        {role === 'Admin' && (
          <NavLink 
            to="/admin" 
            className={({ isActive }) => `sidebar-nav-item ${isActive ? 'active' : ''}`}
          >
            <ShieldCheck className="sidebar-nav-icon" />
            <span className="sidebar-nav-label">Admin Control</span>
          </NavLink>
        )}
      </nav>

      <div className="theme-toggle-container">
        {!isCollapsed && <span className="form-label" style={{ marginBottom: 0 }}>Theme</span>}
        <button 
          className="theme-toggle-btn" 
          onClick={toggleTheme}
          title={theme === 'light' ? 'Switch to Dark Mode' : 'Switch to Light Mode'}
        >
          {theme === 'light' ? <Moon size={18} /> : <Sun size={18} />}
        </button>
      </div>

      <div className="sidebar-profile">
        <div className="sidebar-profile-info">
          <div className="profile-avatar" title={user?.email || 'User'}>
            {userInitial}
          </div>
          <div className="profile-meta">
            <span className="profile-email" title={user?.email || ''}>{user?.email}</span>
            <span className="profile-role">{role}</span>
          </div>
        </div>
        {!isCollapsed && (
          <button 
            className="sidebar-toggle-btn" 
            onClick={handleLogout} 
            title="Sign Out"
            style={{ color: 'var(--danger)' }}
          >
            <LogOut size={18} />
          </button>
        )}
      </div>
    </aside>
  );
};
export default Sidebar;
