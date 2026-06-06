import React, { useEffect, useState, useCallback } from 'react';
import {
  ShieldAlert, RefreshCw, CheckCircle2, Filter,
  AlertTriangle, Skull, Info, Activity, Clock,
  TrendingUp, Eye, Zap, Radio, XCircle, Play
} from 'lucide-react';
import { supabase } from '../supabaseClient';
import { useAuth } from '../contexts/AuthContext';
import { 
  ThreatLogEntry, ThreatSeverity, ThreatEventType, logThreat,
  onFailedLogin, onNewDeviceLogin, onNewLocationLogin, onPasswordResetAttempt, onSuspiciousActivity
} from '../threatService';

// ─── Severity config ─────────────────────────────────────────────────────────

const SEVERITY_CONFIG: Record<ThreatSeverity, { color: string; bg: string; icon: React.ReactNode; label: string }> = {
  Critical: { color: 'var(--danger)', bg: 'rgba(239,68,68,0.12)', icon: <Skull size={14}/>, label: 'Critical' },
  High:     { color: '#f97316',       bg: 'rgba(249,115,22,0.12)',  icon: <AlertTriangle size={14}/>, label: 'High' },
  Medium:   { color: 'var(--warning)',bg: 'rgba(234,179,8,0.12)',   icon: <AlertTriangle size={14}/>, label: 'Medium' },
  Low:      { color: 'var(--success)',bg: 'rgba(16,185,129,0.12)',  icon: <Info size={14}/>, label: 'Low' },
};

const EVENT_LABELS: Record<ThreatEventType, string> = {
  FAILED_LOGIN: 'Failed Login',
  BRUTE_FORCE_DETECTED: 'Brute Force Attack',
  MULTI_LOCATION_LOGIN: 'Multi-Location Login',
  EXCESSIVE_SCANS: 'Excessive Scans',
  MALICIOUS_SCAN_DETECTED: 'Malicious Content Detected',
  REPEATED_SUSPICIOUS_ACTIVITY: 'Repeated Suspicious Activity',
  ADMIN_ACTION: 'Admin Action',
  ACCOUNT_LOCKOUT: 'Account Lockout Risk',
  PHISHING_CAMPAIGN_DETECTED: 'Phishing Campaign',
  UNAUTHORIZED_ACCESS_ATTEMPT: 'Unauthorized Access',
  NEW_DEVICE_LOGIN: 'New Device Login',
  NEW_LOCATION_LOGIN: 'New Location Login',
  PASSWORD_RESET_ATTEMPT: 'Password Reset Attempt',
  MULTIPLE_LOGIN_ATTEMPTS: 'Multiple Login Attempts',
  HIGH_RISK_PHISHING_SCAN: 'High Risk Phishing Scan',
  SUSPICIOUS_USER_ACTIVITY: 'Suspicious User Activity',
};

// ─── Helper ───────────────────────────────────────────────────────────────────

const timeAgo = (isoStr: string) => {
  const diff = Date.now() - new Date(isoStr).getTime();
  const m = Math.floor(diff / 60000);
  if (m < 1) return 'Just now';
  if (m < 60) return `${m}m ago`;
  const h = Math.floor(m / 60);
  if (h < 24) return `${h}h ago`;
  return `${Math.floor(h / 24)}d ago`;
};

// ─── Component ────────────────────────────────────────────────────────────────

export const ThreatMonitor: React.FC = () => {
  const { user, role } = useAuth();

  const [logs, setLogs] = useState<ThreatLogEntry[]>([]);
  const [loading, setLoading] = useState(true);
  const [filterSeverity, setFilterSeverity] = useState<ThreatSeverity | 'All'>('All');
  const [filterEvent, setFilterEvent] = useState<ThreatEventType | 'All'>('All');
  const [filterResolved, setFilterResolved] = useState<'All' | 'Active' | 'Resolved'>('All');
  const [liveMode, setLiveMode] = useState(true);
  const [selectedLog, setSelectedLog] = useState<ThreatLogEntry | null>(null);
  const [resolving, setResolving] = useState<string | null>(null);
  const [generating, setGenerating] = useState(false);
  const [simMessage, setSimMessage] = useState<string | null>(null);

  const triggerSimulation = async (type: 'failed_login' | 'new_device' | 'new_location' | 'reset' | 'suspicious') => {
    if (!user?.email) return;
    setSimMessage(null);
    try {
      if (type === 'failed_login') {
        await onFailedLogin(user.email, '198.51.100.99');
        setSimMessage('Failed login attempt logged successfully.');
      } else if (type === 'new_device') {
        await onNewDeviceLogin(user.email, 'iPhone 17 Pro Max', '198.51.100.102');
        setSimMessage('New device login alert generated.');
      } else if (type === 'new_location') {
        await onNewLocationLogin(user.email, 'London, United Kingdom', '85.22.40.119');
        setSimMessage('New location login alert logged.');
      } else if (type === 'reset') {
        await onPasswordResetAttempt(user.email, '198.51.100.99');
        setSimMessage('Password reset attempt threat event recorded.');
      } else if (type === 'suspicious') {
        await onSuspiciousActivity(user.email, 'Multiple fast API requests detected', '198.51.100.99');
        setSimMessage('Suspicious user activity event logged.');
      }
      setTimeout(() => setSimMessage(null), 3000);
      fetchLogs();
    } catch (e: any) {
      alert(`Simulation failed: ${e.message}`);
    }
  };

  const fetchLogs = useCallback(async () => {
    setLoading(true);
    let query = supabase.from('threat_logs').select('*');
    
    if (role !== 'Admin' && user?.id) {
      query = query.eq('user_id', user.id);
    }
    
    const { data, error } = await query
      .order('created_at', { ascending: false })
      .limit(200);
      
    if (!error && data) setLogs(data as ThreatLogEntry[]);
    setLoading(false);
  }, [role, user?.id]);

  // Real-time subscription
  useEffect(() => {
    fetchLogs();
    if (!liveMode) return;
    const channel = supabase.channel('threat_logs_realtime')
      .on('postgres_changes', { event: '*', schema: 'public', table: 'threat_logs' }, fetchLogs)
      .subscribe();
    return () => { supabase.removeChannel(channel); };
  }, [fetchLogs, liveMode]);

  // Resolve/reopen a log entry
  const toggleResolve = async (log: ThreatLogEntry) => {
    setResolving(log.id);
    await supabase.from('threat_logs').update({ resolved: !log.resolved }).eq('id', log.id);
    setLogs(prev => prev.map(l => l.id === log.id ? { ...l, resolved: !l.resolved } : l));
    if (selectedLog?.id === log.id) setSelectedLog(prev => prev ? { ...prev, resolved: !prev.resolved } : null);
    setResolving(null);
  };

  // Generate demo threat events for testing
  const generateDemoThreats = async () => {
    setGenerating(true);
    const demos: Parameters<typeof logThreat>[0][] = [
      { event_type: 'BRUTE_FORCE_DETECTED', severity: 'Critical', description: 'Brute-force attack detected: 8 failed logins in 15 minutes for admin@target.com', user_email: 'admin@target.com', ip_address: '185.220.101.42', metadata: { failed_count: 8, window_minutes: 15 } },
      { event_type: 'PHISHING_CAMPAIGN_DETECTED', severity: 'Critical', description: 'Phishing campaign: 5 malicious URLs submitted in 10 minutes from same session', metadata: { malicious_count: 5, window_minutes: 10 } },
      { event_type: 'MULTI_LOCATION_LOGIN', severity: 'High', description: 'Account accessed from 4 different IP addresses within 24 hours', user_email: user?.email ?? 'operator@cybershield.ai', ip_address: '91.240.23.155', metadata: { unique_ips: ['91.240.23.155', '103.77.12.44', '185.162.235.7', '5.188.11.22'], window_hours: 24 } },
      { event_type: 'MALICIOUS_SCAN_DETECTED', severity: 'High', description: 'Malicious URL detected (97% confidence): http://192.168.1.1/paypal-verify-login', ip_address: '103.77.12.44', metadata: { confidence: 97, target: 'http://192.168.1.1/paypal-verify-login', scan_type: 'URL' } },
      { event_type: 'ACCOUNT_LOCKOUT', severity: 'High', description: 'Multiple failed logins: 4 attempts for finance@corp.com in last 15 minutes', user_email: 'finance@corp.com', ip_address: '45.142.212.100', metadata: { failed_count: 4 } },
      { event_type: 'EXCESSIVE_SCANS', severity: 'Medium', description: 'Excessive scan rate: 18 scans submitted in 5 minutes', user_email: user?.email ?? 'operator@cybershield.ai', metadata: { scan_count: 18, window_minutes: 5 } },
      { event_type: 'FAILED_LOGIN', severity: 'Low', description: 'Failed login attempt for account: user@company.com', user_email: 'user@company.com', ip_address: '72.14.204.99', metadata: { timestamp: new Date().toISOString() } },
      { event_type: 'ADMIN_ACTION', severity: 'Low', description: `Admin action: Threat alert status updated on threat_alert`, user_email: user?.email ?? 'admin@cybershield.ai', metadata: { action: 'UPDATE_THREAT_STATUS', target_type: 'threat_alert' } },
    ];

    for (const demo of demos) {
      await logThreat(demo);
      await new Promise(r => setTimeout(r, 200));
    }
    setGenerating(false);
    fetchLogs();
  };

  // Filtered logs
  const filtered = logs.filter(l => {
    if (filterSeverity !== 'All' && l.severity !== filterSeverity) return false;
    if (filterEvent !== 'All' && l.event_type !== filterEvent) return false;
    if (filterResolved === 'Active' && l.resolved) return false;
    if (filterResolved === 'Resolved' && !l.resolved) return false;
    return true;
  });

  // Stats
  const stats = {
    total: logs.length,
    active: logs.filter(l => !l.resolved).length,
    critical: logs.filter(l => l.severity === 'Critical' && !l.resolved).length,
    high: logs.filter(l => l.severity === 'High' && !l.resolved).length,
    medium: logs.filter(l => l.severity === 'Medium' && !l.resolved).length,
    low: logs.filter(l => l.severity === 'Low' && !l.resolved).length,
    resolved: logs.filter(l => l.resolved).length,
  };

  // Group by event type for sparkline
  const eventCounts = Object.keys(EVENT_LABELS).reduce((acc, k) => {
    acc[k] = logs.filter(l => l.event_type === k).length;
    return acc;
  }, {} as Record<string, number>);

  return (
    <div className="dashboard-container">

      {/* Header */}
      <header className="dashboard-header">
        <div className="dashboard-title-area">
          <h1 style={{ display: 'flex', alignItems: 'center', gap: '0.75rem' }}>
            <ShieldAlert size={28} style={{ color: 'var(--primary)' }}/>
            {role === 'Admin' ? 'Threat Monitoring Center' : 'Personal Threat Monitoring'}
          </h1>
          <p className="auth-subtitle">
            {role === 'Admin' 
              ? 'Real-time threat detection, log analysis and incident resolution' 
              : 'Security threat logs and access anomalies related only to your account'}
          </p>
        </div>
        <div style={{ display: 'flex', gap: '0.75rem', alignItems: 'center', flexWrap: 'wrap' }}>
          <div className={`system-status-indicator ${liveMode ? '' : 'status-offline'}`}
            style={{ cursor: 'pointer', padding: '0.4rem 0.8rem', borderRadius: '20px',
              background: liveMode ? 'rgba(16,185,129,0.1)' : 'rgba(107,114,128,0.1)',
              border: `1px solid ${liveMode ? 'rgba(16,185,129,0.3)' : 'rgba(107,114,128,0.3)'}`,
              color: liveMode ? 'var(--success)' : 'var(--text-muted)' }}
            onClick={() => setLiveMode(p => !p)}>
            <Radio size={13}/>
            <span style={{ fontWeight: 600 }}>{liveMode ? 'LIVE' : 'PAUSED'}</span>
          </div>
          <button className="btn btn-secondary btn-small" onClick={fetchLogs} disabled={loading}>
            <RefreshCw size={14} className={loading ? 'spin' : ''}/> Refresh
          </button>
          {role === 'Admin' && (
            <button className="btn btn-primary btn-small" onClick={generateDemoThreats} disabled={generating}>
              <Zap size={14}/> {generating ? 'Generating...' : 'Generate Demo Threats'}
            </button>
          )}
        </div>
      </header>

      {/* Stats Row */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(130px, 1fr))', gap: '1rem', marginBottom: '2rem' }}>
        {[
          { label: 'Total Logs', val: stats.total, color: 'var(--text-primary)', icon: <Activity size={18}/> },
          { label: 'Active Threats', val: stats.active, color: '#f97316', icon: <AlertTriangle size={18}/> },
          { label: 'Critical', val: stats.critical, color: 'var(--danger)', icon: <Skull size={18}/> },
          { label: 'High', val: stats.high, color: '#f97316', icon: <AlertTriangle size={18}/> },
          { label: 'Medium', val: stats.medium, color: 'var(--warning)', icon: <AlertTriangle size={18}/> },
          { label: 'Low', val: stats.low, color: 'var(--success)', icon: <Info size={18}/> },
          { label: 'Resolved', val: stats.resolved, color: 'var(--text-muted)', icon: <CheckCircle2 size={18}/> },
        ].map(s => (
          <div key={s.label} className="card" style={{ padding: '1rem', textAlign: 'center' }}>
            <div style={{ color: s.color, marginBottom: '0.3rem', display: 'flex', justifyContent: 'center' }}>{s.icon}</div>
            <div style={{ fontSize: '1.6rem', fontWeight: 800, color: s.color, lineHeight: 1 }}>{loading ? '…' : s.val}</div>
            <div style={{ fontSize: '0.72rem', color: 'var(--text-secondary)', marginTop: '0.2rem', textTransform: 'uppercase', letterSpacing: '0.05em' }}>{s.label}</div>
          </div>
        ))}
      </div>
      {/* Simulator Widget for Sandbox testing (Standard User only) */}
      {role !== 'Admin' && (
        <div className="card" style={{ marginBottom: '1.5rem', border: '1px dashed var(--border-color)', background: 'linear-gradient(135deg, var(--bg-secondary) 0%, rgba(99,102,241,0.02) 100%)' }}>
          <h3 style={{ fontSize: '0.9rem', marginBottom: '0.4rem', display: 'flex', alignItems: 'center', gap: '0.4rem' }}>
            <Play size={14} style={{ color: 'var(--primary)' }} />
            Threat Event Simulator (User Sandbox)
          </h3>
          <p style={{ fontSize: '0.78rem', color: 'var(--text-secondary)', marginBottom: '0.75rem' }}>
            Simulate personal security threat events for your profile to test real-time monitoring and SMTP email dispatch alerts.
          </p>
          {simMessage && <div className="alert alert-success" style={{ marginBottom: '0.75rem', padding: '0.5rem 0.75rem', fontSize: '0.8rem' }}>{simMessage}</div>}
          <div style={{ display: 'flex', gap: '0.5rem', flexWrap: 'wrap' }}>
            <button className="btn btn-secondary btn-small" style={{ fontSize: '0.73rem', padding: '0.3rem 0.6rem' }} onClick={() => triggerSimulation('failed_login')}>Log Failed Login</button>
            <button className="btn btn-secondary btn-small" style={{ fontSize: '0.73rem', padding: '0.3rem 0.6rem' }} onClick={() => triggerSimulation('new_device')}>Log New Device Alert</button>
            <button className="btn btn-secondary btn-small" style={{ fontSize: '0.73rem', padding: '0.3rem 0.6rem' }} onClick={() => triggerSimulation('new_location')}>Log New Location</button>
            <button className="btn btn-secondary btn-small" style={{ fontSize: '0.73rem', padding: '0.3rem 0.6rem' }} onClick={() => triggerSimulation('reset')}>Log Password Reset</button>
            <button className="btn btn-secondary btn-small" style={{ fontSize: '0.73rem', padding: '0.3rem 0.6rem' }} onClick={() => triggerSimulation('suspicious')}>Log Suspicious Action</button>
          </div>
        </div>
      )}
      {/* Event Distribution Chart */}
      <div className="card" style={{ marginBottom: '2rem' }}>
        <div className="metric-card-header">
          <h3 style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
            <TrendingUp size={18} style={{ color: 'var(--primary)' }}/> Threat Event Distribution
          </h3>
          <span style={{ fontSize: '0.75rem', color: 'var(--text-secondary)' }}>All-time event type breakdown</span>
        </div>
        <div style={{ display: 'flex', gap: '0.75rem', flexWrap: 'wrap', marginTop: '0.5rem' }}>
          {Object.entries(EVENT_LABELS).map(([key, label]) => {
            const count = eventCounts[key] || 0;
            const maxCount = Math.max(...Object.values(eventCounts), 1);
            const pct = (count / maxCount) * 100;
            return (
              <div key={key}
                onClick={() => setFilterEvent(filterEvent === key as ThreatEventType ? 'All' : key as ThreatEventType)}
                className="card"
                style={{
                  flex: '1 1 150px', minWidth: '140px', padding: '0.75rem',
                  cursor: 'pointer', border: filterEvent === key ? '1px solid var(--primary)' : '1px solid var(--border-color)',
                  background: filterEvent === key ? 'rgba(99,102,241,0.08)' : 'var(--bg-secondary)'
                }}>
                <div style={{ fontWeight: 600, fontSize: '0.78rem', color: 'var(--text-primary)', marginBottom: '0.4rem' }}>{label}</div>
                <div style={{ background: 'var(--bg-primary)', borderRadius: '4px', height: '6px', overflow: 'hidden', marginBottom: '0.3rem' }}>
                  <div style={{ width: `${pct}%`, height: '100%', background: 'var(--primary)', borderRadius: '4px', transition: 'width 0.6s ease' }}/>
                </div>
                <div style={{ fontSize: '1.1rem', fontWeight: 700, color: count > 0 ? 'var(--text-primary)' : 'var(--text-muted)' }}>{count}</div>
              </div>
            );
          })}
        </div>
      </div>

      {/* Filters + Log Table */}
      <div style={{ display: 'grid', gridTemplateColumns: selectedLog ? '1fr 400px' : '1fr', gap: '1.5rem', alignItems: 'start' }}>

        <div className="card" style={{ padding: 0, overflow: 'hidden' }}>
          {/* Filter Bar */}
          <div style={{ padding: '1rem 1.25rem', borderBottom: '1px solid var(--border-color)', display: 'flex', gap: '0.75rem', flexWrap: 'wrap', alignItems: 'center' }}>
            <Filter size={15} style={{ color: 'var(--text-secondary)' }}/>
            <span style={{ fontSize: '0.8rem', fontWeight: 600, color: 'var(--text-secondary)', textTransform: 'uppercase', letterSpacing: '0.05em' }}>Filters:</span>

            {/* Severity Filter */}
            <div style={{ display: 'flex', gap: '0.3rem', flexWrap: 'wrap' }}>
              {(['All', 'Critical', 'High', 'Medium', 'Low'] as const).map(s => (
                <button key={s} onClick={() => setFilterSeverity(s)}
                  className={`btn btn-small ${filterSeverity === s ? 'btn-primary' : 'btn-secondary'}`}
                  style={{ padding: '0.2rem 0.6rem', fontSize: '0.75rem', height: 'auto' }}>
                  {s}
                </button>
              ))}
            </div>

            <div style={{ width: '1px', height: '20px', background: 'var(--border-color)' }}/>

            {/* Status Filter */}
            <div style={{ display: 'flex', gap: '0.3rem' }}>
              {(['All', 'Active', 'Resolved'] as const).map(s => (
                <button key={s} onClick={() => setFilterResolved(s)}
                  className={`btn btn-small ${filterResolved === s ? 'btn-primary' : 'btn-secondary'}`}
                  style={{ padding: '0.2rem 0.6rem', fontSize: '0.75rem', height: 'auto' }}>
                  {s}
                </button>
              ))}
            </div>

            <span style={{ marginLeft: 'auto', fontSize: '0.78rem', color: 'var(--text-muted)' }}>
              {filtered.length} of {logs.length} entries
            </span>
            {filterSeverity !== 'All' || filterEvent !== 'All' || filterResolved !== 'All' ? (
              <button className="btn btn-secondary btn-small" style={{ padding: '0.2rem 0.5rem', fontSize: '0.72rem', height: 'auto' }}
                onClick={() => { setFilterSeverity('All'); setFilterEvent('All'); setFilterResolved('All'); }}>
                Clear
              </button>
            ) : null}
          </div>

          {/* Log Table */}
          {loading ? (
            <div style={{ padding: '2rem' }}>
              <div className="skeleton skeleton-title" style={{ width: '200px' }}></div>
              <div style={{ display: 'flex', flexDirection: 'column', gap: '0.75rem' }}>
                <div className="skeleton skeleton-text" style={{ width: '100%', height: '16px' }}></div>
                <div className="skeleton skeleton-text" style={{ width: '98%', height: '16px' }}></div>
                <div className="skeleton skeleton-text" style={{ width: '99%', height: '16px' }}></div>
                <div className="skeleton skeleton-text" style={{ width: '95%', height: '16px' }}></div>
                <div className="skeleton skeleton-text" style={{ width: '90%', height: '16px' }}></div>
              </div>
            </div>
          ) : filtered.length === 0 ? (
            <div style={{ padding: '3rem', textAlign: 'center' }}>
              <ShieldAlert size={40} style={{ color: 'var(--text-muted)', marginBottom: '1rem', display: 'inline-block' }}/>
              <p style={{ color: 'var(--text-secondary)' }}>No threat logs match your filters.</p>
              {role === 'Admin' && logs.length === 0 && (
                <p style={{ color: 'var(--text-muted)', fontSize: '0.85rem', marginTop: '0.5rem' }}>
                  Click "Generate Demo Threats" to populate the monitoring log with sample events.
                </p>
              )}
            </div>
          ) : (
            <div style={{ overflowX: 'auto' }}>
              <table className="cyber-table" style={{ tableLayout: 'fixed', width: '100%' }}>
                <thead>
                  <tr>
                    <th style={{ width: '110px' }}>Severity</th>
                    <th style={{ width: '170px' }}>Event Type</th>
                    <th>Description</th>
                    <th style={{ width: '130px' }}>User / IP</th>
                    <th style={{ width: '85px' }}>Time</th>
                    <th style={{ width: '90px' }}>Status</th>
                  </tr>
                </thead>
                <tbody>
                  {filtered.map(log => {
                    const sev = SEVERITY_CONFIG[log.severity];
                    return (
                      <tr key={log.id}
                        onClick={() => setSelectedLog(selectedLog?.id === log.id ? null : log)}
                        style={{
                          cursor: 'pointer',
                          opacity: log.resolved ? 0.55 : 1,
                          background: selectedLog?.id === log.id ? 'rgba(99,102,241,0.07)' : undefined,
                          borderLeft: `3px solid ${log.resolved ? 'transparent' : sev.color}`,
                        }}>
                        <td>
                          <span style={{ display: 'inline-flex', alignItems: 'center', gap: '0.3rem', fontWeight: 700, color: sev.color, fontSize: '0.82rem' }}>
                            {sev.icon} {log.severity}
                          </span>
                        </td>
                        <td style={{ fontSize: '0.82rem', fontWeight: 500 }}>
                          {EVENT_LABELS[log.event_type] ?? log.event_type}
                        </td>
                        <td style={{ fontSize: '0.82rem', maxWidth: '280px', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}
                          title={log.description}>{log.description}</td>
                        <td style={{ fontSize: '0.75rem', fontFamily: 'var(--font-mono)', color: 'var(--text-secondary)' }}>
                          <div style={{ overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{log.user_email ?? '—'}</div>
                          <div style={{ color: 'var(--text-muted)' }}>{log.ip_address ?? ''}</div>
                        </td>
                        <td style={{ fontSize: '0.75rem', color: 'var(--text-secondary)', whiteSpace: 'nowrap' }}>
                          <Clock size={11} style={{ marginRight: '3px', verticalAlign: 'middle' }}/>
                          {timeAgo(log.created_at)}
                        </td>
                        <td>
                          <button
                            className={`btn btn-small ${log.resolved ? 'btn-secondary' : 'btn-primary'}`}
                            style={{ padding: '0.2rem 0.5rem', fontSize: '0.72rem', height: 'auto', width: '100%' }}
                            onClick={e => { e.stopPropagation(); toggleResolve(log); }}
                            disabled={resolving === log.id}>
                            {resolving === log.id ? '...' : log.resolved ? 'Reopen' : 'Resolve'}
                          </button>
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          )}
        </div>

        {/* Detail Panel */}
        {selectedLog && (() => {
          const sev = SEVERITY_CONFIG[selectedLog.severity];
          return (
            <div className="card" style={{ position: 'sticky', top: '1rem', border: `1px solid ${sev.color}40` }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: '1rem' }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                  <div style={{ width: '36px', height: '36px', borderRadius: '8px', background: sev.bg, display: 'flex', alignItems: 'center', justifyContent: 'center', color: sev.color }}>
                    {sev.icon}
                  </div>
                  <div>
                    <div style={{ fontWeight: 700, fontSize: '0.9rem' }}>{EVENT_LABELS[selectedLog.event_type]}</div>
                    <div style={{ fontSize: '0.75rem', color: sev.color, fontWeight: 600 }}>{selectedLog.severity}</div>
                  </div>
                </div>
                <button onClick={() => setSelectedLog(null)} className="btn btn-secondary btn-small"
                  style={{ padding: '0.2rem 0.4rem', height: 'auto' }}>
                  <XCircle size={14}/>
                </button>
              </div>

              <div style={{ display: 'flex', flexDirection: 'column', gap: '0.75rem', fontSize: '0.85rem' }}>
                {/* Description */}
                <div style={{ background: 'var(--bg-primary)', borderRadius: 'var(--radius-md)', padding: '0.75rem', lineHeight: 1.7 }}>
                  <div style={{ fontSize: '0.7rem', textTransform: 'uppercase', letterSpacing: '0.05em', color: 'var(--text-muted)', marginBottom: '0.3rem', fontWeight: 700 }}>Description</div>
                  {selectedLog.description}
                </div>

                {/* Meta */}
                <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '0.5rem' }}>
                  {[
                    { label: 'Time', val: new Date(selectedLog.created_at).toLocaleString() },
                    { label: 'Status', val: selectedLog.resolved ? '✅ Resolved' : '🔴 Active' },
                    { label: 'User Email', val: selectedLog.user_email ?? '—' },
                    { label: 'IP Address', val: selectedLog.ip_address ?? '—' },
                  ].map(f => (
                    <div key={f.label} style={{ background: 'var(--bg-primary)', borderRadius: '6px', padding: '0.5rem 0.6rem' }}>
                      <div style={{ fontSize: '0.68rem', color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.05em', marginBottom: '0.1rem' }}>{f.label}</div>
                      <div style={{ fontFamily: 'var(--font-mono)', fontSize: '0.78rem', wordBreak: 'break-all' }}>{f.val}</div>
                    </div>
                  ))}
                </div>

                {/* Metadata JSON */}
                {Object.keys(selectedLog.metadata || {}).length > 0 && (
                  <div>
                    <div style={{ fontSize: '0.7rem', textTransform: 'uppercase', letterSpacing: '0.05em', color: 'var(--text-muted)', marginBottom: '0.3rem', fontWeight: 700 }}>Raw Metadata</div>
                    <pre style={{
                      background: 'var(--bg-primary)', border: '1px solid var(--border-color)',
                      borderRadius: '6px', padding: '0.6rem', fontSize: '0.73rem',
                      fontFamily: 'var(--font-mono)', color: 'var(--text-secondary)',
                      overflowX: 'auto', maxHeight: '180px', overflowY: 'auto', margin: 0
                    }}>
                      {JSON.stringify(selectedLog.metadata, null, 2)}
                    </pre>
                  </div>
                )}

                {/* Threat Recommendations */}
                <div style={{ background: sev.bg, borderRadius: 'var(--radius-md)', padding: '0.75rem', border: `1px solid ${sev.color}30` }}>
                  <div style={{ fontSize: '0.7rem', textTransform: 'uppercase', letterSpacing: '0.05em', color: sev.color, marginBottom: '0.4rem', fontWeight: 700, display: 'flex', alignItems: 'center', gap: '0.3rem' }}>
                    <Eye size={11}/> Recommended Response
                  </div>
                  <div style={{ fontSize: '0.82rem', lineHeight: 1.7 }}>
                    {selectedLog.event_type === 'BRUTE_FORCE_DETECTED' && '🚫 Block the source IP immediately. Lock the targeted account. Review login logs for compromise indicators.'}
                    {selectedLog.event_type === 'PHISHING_CAMPAIGN_DETECTED' && '🔍 Review all submitted scan targets. Correlate source session. Consider temporary rate limiting for this user.'}
                    {selectedLog.event_type === 'MULTI_LOCATION_LOGIN' && '📧 Notify the account holder via a separate channel. Request re-authentication and enable 2FA if not active.'}
                    {selectedLog.event_type === 'MALICIOUS_SCAN_DETECTED' && '📋 Review the flagged content. Add the malicious domain/sender to the blocklist. Notify the scanning user.'}
                    {selectedLog.event_type === 'FAILED_LOGIN' && '👀 Monitor for additional attempts. If frequency increases, escalate to High severity.'}
                    {selectedLog.event_type === 'ACCOUNT_LOCKOUT' && '🔒 Temporarily lock the account and notify the user via email. Verify identity before re-enabling.'}
                    {selectedLog.event_type === 'EXCESSIVE_SCANS' && '⚠️ Investigate whether this is automated scanning. Consider applying rate limiting to this session.'}
                    {selectedLog.event_type === 'ADMIN_ACTION' && '📝 Admin action logged for audit trail. Review if the action was expected and authorized.'}
                    {selectedLog.event_type === 'UNAUTHORIZED_ACCESS_ATTEMPT' && '🚨 Investigate the access pattern. Block the source IP and alert the security team immediately.'}
                    {selectedLog.event_type === 'REPEATED_SUSPICIOUS_ACTIVITY' && '🔁 Pattern of suspicious behavior detected. Escalate to security team review.'}
                  </div>
                </div>

                {/* Action Button */}
                <button
                  className={`btn ${selectedLog.resolved ? 'btn-secondary' : 'btn-primary'}`}
                  onClick={() => toggleResolve(selectedLog)}
                  disabled={resolving === selectedLog.id}
                  style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', gap: '0.5rem' }}>
                  {resolving === selectedLog.id ? 'Updating...' : selectedLog.resolved
                    ? <><XCircle size={15}/> Reopen Incident</>
                    : <><CheckCircle2 size={15}/> Mark as Resolved</>}
                </button>
              </div>
            </div>
          );
        })()}
      </div>
    </div>
  );
};

export default ThreatMonitor;
