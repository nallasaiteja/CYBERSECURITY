import React from 'react';
import { useNavigate } from 'react-router-dom';
import { AlertOctagon, ArrowLeft } from 'lucide-react';

export const Unauthorized: React.FC = () => {
  const navigate = useNavigate();

  return (
    <div className="auth-container">
      <div className="auth-card" style={{ textAlign: 'center' }}>
        <div className="unauthorized-icon">
          <AlertOctagon size={64} style={{ color: 'var(--danger)', display: 'inline-block' }} />
        </div>
        <h2 className="auth-title" style={{ color: 'var(--danger)', background: 'none', WebkitTextFillColor: 'initial' }}>
          Access Forbidden
        </h2>
        <p className="auth-subtitle" style={{ marginTop: '0.75rem', marginBottom: '2rem' }}>
          You do not have the required administrative clearance to access this control node. 
          This event has been logged to audit files.
        </p>

        <button 
          onClick={() => navigate('/dashboard')} 
          className="btn btn-secondary"
        >
          <ArrowLeft size={16} />
          Return to Dashboard
        </button>
      </div>
    </div>
  );
};
export default Unauthorized;
