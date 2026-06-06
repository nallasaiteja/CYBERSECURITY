import React, { useState } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import { Mail, Lock, Shield, UserPlus } from 'lucide-react';
import { supabase } from '../supabaseClient';

export const Signup: React.FC = () => {
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');
  const [role, setRole] = useState<'Admin' | 'User'>('User');
  const [adminKey, setAdminKey] = useState('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [success, setSuccess] = useState<string | null>(null);
  const navigate = useNavigate();

  const handleSignup = async (e: React.FormEvent) => {
    e.preventDefault();
    setLoading(true);
    setError(null);
    setSuccess(null);

    if (password !== confirmPassword) {
      setError('Passphrases do not match.');
      setLoading(false);
      return;
    }

    if (role === 'Admin' && adminKey !== 'CYBER_SHIELD_2026') {
      setError('Access Denied: Invalid Admin Access Passcode.');
      setLoading(false);
      return;
    }

    if (password.length < 6) {
      setError('Passphrase must be at least 6 characters.');
      setLoading(false);
      return;
    }

    try {
      const { data, error: signUpError } = await supabase.auth.signUp({
        email,
        password,
        options: {
          data: {
            role: role // Triggers public.profiles creation with selected role
          }
        }
      });

      if (signUpError) throw signUpError;

      if (data.user) {
        setSuccess('Account created successfully! Redirecting to secure portal...');
        setTimeout(() => {
          navigate('/dashboard');
        }, 1500);
      }
    } catch (err: any) {
      setError(err.message || 'Registration failed. Try again.');
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
          <p className="auth-subtitle">Initialize new security operator access</p>
        </div>

        {error && <div className="alert alert-danger">{error}</div>}
        {success && <div className="alert alert-success">{success}</div>}

        <form onSubmit={handleSignup}>
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
            <label className="form-label" htmlFor="password">Passphrase</label>
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

          <div className="form-group">
            <label className="form-label" htmlFor="confirmPassword">Confirm Passphrase</label>
            <div className="input-wrapper">
              <Lock className="input-icon" />
              <input
                id="confirmPassword"
                type="password"
                className="form-input"
                placeholder="••••••••••••"
                value={confirmPassword}
                onChange={(e) => setConfirmPassword(e.target.value)}
                required
              />
            </div>
          </div>

          <div className="form-group">
            <label className="form-label">System Role Authorization</label>
            <div className="select-role-container">
              <div 
                className={`role-option ${role === 'User' ? 'active' : ''}`}
                onClick={() => setRole('User')}
              >
                Standard Operator (User)
              </div>
              <div 
                className={`role-option ${role === 'Admin' ? 'active' : ''}`}
                onClick={() => setRole('Admin')}
              >
                Security Admin (Admin)
              </div>
            </div>
          </div>

          {role === 'Admin' && (
            <div className="form-group" style={{ animation: 'fadeIn 0.3s ease-out' }}>
              <label className="form-label" htmlFor="adminKey">Admin Access Code</label>
              <div className="input-wrapper">
                <Lock className="input-icon" />
                <input
                  id="adminKey"
                  type="password"
                  className="form-input"
                  placeholder="Enter secret admin key..."
                  value={adminKey}
                  onChange={(e) => setAdminKey(e.target.value)}
                  required
                />
              </div>
            </div>
          )}

          <button type="submit" className="btn btn-primary" disabled={loading} style={{ marginTop: '1rem' }}>
            {loading ? 'Authorizing Operator...' : 'Create Access Token'}
            {!loading && <UserPlus size={18} />}
          </button>
        </form>

        <div className="auth-footer">
          Already registered?{' '}
          <Link to="/login" className="auth-link">
            Authenticate Operator (Sign In)
          </Link>
        </div>
      </div>
    </div>
  );
};
export default Signup;
