import React, { useState } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import { Mail, Lock, Shield, ArrowRight } from 'lucide-react';
import { supabase } from '../supabaseClient';
import { onFailedLogin, onSuccessfulLogin } from '../threatService';
import { checkFailedLoginAlert } from '../alertService';

export const Login: React.FC = () => {
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [success, setSuccess] = useState<string | null>(null);
  const navigate = useNavigate();

  const handleLogin = async (e: React.FormEvent) => {
    e.preventDefault();
    setLoading(true);
    setError(null);
    setSuccess(null);

    try {
      const { data, error: signInError } = await supabase.auth.signInWithPassword({
        email,
        password,
      });

      if (signInError) throw signInError;

      if (data.user) {
        // Check if suspended
        const { data: profile } = await supabase
          .from('profiles')
          .select('is_suspended')
          .eq('id', data.user.id)
          .maybeSingle();

        if (profile?.is_suspended) {
          await supabase.auth.signOut();
          throw new Error('This operator account has been suspended by an administrator.');
        }

        // Log successful login for multi-location monitoring
        await onSuccessfulLogin(email);
        setSuccess('Authentication successful! Initializing secure session...');
        setTimeout(() => {
          navigate('/dashboard');
        }, 1200);
      }
    } catch (err: any) {
      // Auto-log failed login attempt to threat monitoring
      await onFailedLogin(email);
      // Also record in failed_logins table
      await supabase.from('failed_logins').insert([{ email, ip_address: null, attempted_at: new Date().toISOString() }]).then(() => {});
      // Alert engine: check if threshold exceeded (>5 in 10 min)
      await checkFailedLoginAlert(email);
      setError(err.message || 'Login failed. Please check your credentials.');
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
          <p className="auth-subtitle">Access your security intelligence hub</p>
        </div>

        {error && <div className="alert alert-danger">{error}</div>}
        {success && <div className="alert alert-success">{success}</div>}

        <form onSubmit={handleLogin}>
          <div className="form-group">
            <label className="form-label" htmlFor="email">Security Identifier (Email)</label>
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

          <div className="form-group">
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
              <label className="form-label" htmlFor="password">Passphrase</label>
              <Link to="/forgot-password" style={{ fontSize: '0.8rem', marginBottom: '0.5rem' }} className="auth-link">
                Recover Passphrase?
              </Link>
            </div>
            <div className="input-wrapper">
              <Lock className="input-icon" />
              <input
                id="password"
                type="password"
                className="form-input"
                placeholder="••••••••••••"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                required
              />
            </div>
          </div>

          <button type="submit" className="btn btn-primary" disabled={loading} style={{ marginTop: '1rem' }}>
            {loading ? 'Decrypting Credentials...' : 'Authenticate'}
            {!loading && <ArrowRight size={18} />}
          </button>
        </form>

        <div className="auth-footer">
          New operator?{' '}
          <Link to="/signup" className="auth-link">
            Request Access Key (Sign Up)
          </Link>
        </div>
      </div>
    </div>
  );
};
export default Login;
