import React from 'react';
import { useNavigate } from 'react-router-dom';
import { ShieldAlert, LogOut } from 'lucide-react';
import { useAuth } from '../contexts/AuthContext';

export const Suspended: React.FC = () => {
  const { signOut } = useAuth();
  const navigate = useNavigate();

  const handleLogout = async () => {
    await signOut();
    navigate('/login');
  };

  return (
    <div className="auth-container">
      <div className="auth-card" style={{ textAlign: 'center', border: '1px solid var(--danger)' }}>
        <div className="unauthorized-icon" style={{ animation: 'pulse 2s infinite' }}>
          <ShieldAlert size={64} style={{ color: 'var(--danger)', display: 'inline-block' }} />
        </div>
        <h2 className="auth-title" style={{ color: 'var(--danger)', background: 'none', WebkitTextFillColor: 'initial', fontSize: '1.8rem', fontWeight: 'bold' }}>
          Account Suspended
        </h2>
        <p className="auth-subtitle" style={{ marginTop: '1rem', marginBottom: '2rem', color: 'var(--text-secondary)' }}>
          Your operator profile has been suspended by system security administration. 
          All active authorization tokens have been revoked.
          <br /><br />
          If you believe this is an error or to request reactivation, please contact your Security Operations Center (SOC) supervisor.
        </p>

        <button 
          onClick={handleLogout} 
          className="btn btn-danger"
          style={{ width: '100%', display: 'flex', alignItems: 'center', justifyContent: 'center', gap: '0.5rem' }}
        >
          <LogOut size={16} />
          Sign Out of Session
        </button>
      </div>
    </div>
  );
};

export default Suspended;
