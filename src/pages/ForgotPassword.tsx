import React, { useState } from 'react';
import { Link } from 'react-router-dom';
import { Mail, Shield, KeyRound, ArrowLeft } from 'lucide-react';
import { supabase } from '../supabaseClient';

export const ForgotPassword: React.FC = () => {
  const [email, setEmail] = useState('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [success, setSuccess] = useState<string | null>(null);

  const handleReset = async (e: React.FormEvent) => {
    e.preventDefault();
    setLoading(true);
    setError(null);
    setSuccess(null);

    try {
      const { error: resetError } = await supabase.auth.resetPasswordForEmail(email, {
        redirectTo: `${window.location.origin}/login`,
      });

      if (resetError) throw resetError;

      setSuccess('Recovery link successfully dispatched. Please inspect your inbox.');
    } catch (err: any) {
      setError(err.message || 'Passphrase recovery request failed.');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="auth-container">
      <div className="auth-card">
        <div className="auth-header">
          <div className="auth-logo">
            <Shield size={28} />
          </div>
          <h2 className="auth-title">CyberShield AI</h2>
          <p className="auth-subtitle">Recover operator passphrase access</p>
        </div>

        {error && <div className="alert alert-danger">{error}</div>}
        {success && <div className="alert alert-success">{success}</div>}

        <form onSubmit={handleReset}>
          <div className="form-group">
            <label className="form-label" htmlFor="email">Registered Security Identifier (Email)</label>
            <div className="input-wrapper">
              <Mail className="input-icon" />
              <input
                id="email"
                type="email"
                className="form-input"
                placeholder="operator@cybershield.ai"
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                required
              />
            </div>
          </div>

          <button type="submit" className="btn btn-primary" disabled={loading} style={{ marginTop: '1.5rem' }}>
            {loading ? 'Dispatched Request...' : 'Dispatch Recovery Link'}
            {!loading && <KeyRound size={18} />}
          </button>
        </form>

        <div className="auth-footer" style={{ display: 'flex', justifyContent: 'center', gap: '0.5rem', marginTop: '2rem' }}>
          <Link to="/login" className="auth-link" style={{ display: 'inline-flex', alignItems: 'center', gap: '0.25rem' }}>
            <ArrowLeft size={14} /> Back to Authentication
          </Link>
        </div>
      </div>
    </div>
  );
};
export default ForgotPassword;
