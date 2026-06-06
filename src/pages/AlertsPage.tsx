import React, { useEffect, useState, useCallback } from 'react';
import {
  Bell, BellOff, CheckCheck, Trash2, RefreshCw, Radio,
  AlertTriangle, Skull, Info, Filter, Clock,
  Zap, Eye, X
} from 'lucide-react';
import { supabase } from '../supabaseClient';
import {
  AlertEntry, AlertSeverity, AlertType,
  fetchAlerts, markAlertRead, markAllAlertsRead, dismissAlert, fireAlert
} from '../alertService';
import { useAuth } from '../contexts/AuthContext';

// ─── Config ───────────────────────────────────────────────────────────────────

const SEV_CONFIG: Record<AlertSeverity, { color: string; bg: string; border: string; icon: React.ReactNode }> = {
  Critical: { color: 'var(--danger)',  bg: 'rgba(239,68,68,0.08)',  border: 'rgba(239,68,68,0.3)',  icon: <Skull size={15}/> },
  High:     { color: '#f97316',        bg: 'rgba(249,115,22,0.08)', border: 'rgba(249,115,22,0.3)', icon: <AlertTriangle size={15}/> },
  Medium:   { color: 'var(--warning)', bg: 'rgba(234,179,8,0.08)',  border: 'rgba(234,179,8,0.3)',  icon: <AlertTriangle size={15}/> },
  Low:      { color: 'var(--success)', bg: 'rgba(16,185,129,0.08)', border: 'rgba(16,185,129,0.3)', icon: <Info size={15}/> },
};

const TYPE_LABELS: Record<AlertType, string> = {
  EXCESSIVE_FAILED_LOGINS: 'Excessive Failed Logins',
  HIGH_RISK_PHISHING_SCAN: 'High-Risk Phishing Scan',
  REPEATED_SUSPICIOUS_ACTIVITY: 'Repeated Suspicious Activity',
  BRUTE_FORCE_ALERT: 'Brute Force Attack',
  PHISHING_CAMPAIGN_ALERT: 'Phishing Campaign',
  ACCOUNT_COMPROMISE_RISK: 'Account Compromise Risk',
};

const timeAgo = (iso: string) => {
  const d = Date.now() - new Date(iso).getTime();
  const m = Math.floor(d / 60000);
  if (m < 1) return 'Just now';
  if (m < 60) return `${m}m ago`;
  const h = Math.floor(m / 60);
  if (h < 24) return `${h}h ago`;
  return `${Math.floor(h / 24)}d ago`;
};

// ─── Component ────────────────────────────────────────────────────────────────

export const AlertsPage: React.FC = () => {
  const { user, role } = useAuth();

  const [alerts, setAlerts] = useState<AlertEntry[]>([]);
  const [loading, setLoading] = useState(true);
  const [filterSev, setFilterSev] = useState<AlertSeverity | 'All'>('All');
  const [filterType, setFilterType] = useState<AlertType | 'All'>('All');
  const [filterRead, setFilterRead] = useState<'All' | 'Unread' | 'Read'>('All');
  const [selected, setSelected] = useState<AlertEntry | null>(null);
  const [liveMode, setLiveMode] = useState(true);
  const [generating, setGenerating] = useState(false);
  const [actionMsg, setActionMsg] = useState<string | null>(null);

  const load = useCallback(async () => {
    setLoading(true);
    const data = await fetchAlerts(100);
    setAlerts(data);
    setLoading(false);
  }, []);

  useEffect(() => {
    load();
  }, [load]);

  // Real-time subscription for new alerts
  useEffect(() => {
    if (!liveMode) return;
    const ch = supabase.channel('alerts_live')
      .on('postgres_changes', { event: 'INSERT', schema: 'public', table: 'alerts' }, (payload: any) => {
        setAlerts(prev => [payload.new as AlertEntry, ...prev]);
      })
      .on('postgres_changes', { event: 'UPDATE', schema: 'public', table: 'alerts' }, () => load())
      .subscribe();
    return () => { supabase.removeChannel(ch); };
  }, [liveMode, load]);

  const handleRead = async (alert: AlertEntry) => {
    if (!alert.is_read) {
      await markAlertRead(alert.id);
      setAlerts(prev => prev.map(a => a.id === alert.id ? { ...a, is_read: true } : a));
    }
    setSelected(alert.is_read && selected?.id === alert.id ? null : { ...alert, is_read: true });
  };

  const handleDismiss = async (id: string, e?: React.MouseEvent) => {
    e?.stopPropagation();
    await dismissAlert(id);
    setAlerts(prev => prev.filter(a => a.id !== id));
    if (selected?.id === id) setSelected(null);
  };

  const handleMarkAllRead = async () => {
    await markAllAlertsRead();
    setAlerts(prev => prev.map(a => ({ ...a, is_read: true })));
    setActionMsg('All alerts marked as read.');
    setTimeout(() => setActionMsg(null), 3000);
  };

  // Generate demo alerts for testing
  const generateDemos = async () => {
    setGenerating(true);
    const demos: Parameters<typeof fireAlert>[0][] = [
      {
        alert_type: 'EXCESSIVE_FAILED_LOGINS', severity: 'Critical',
        title: '🚨 Excessive Failed Logins Detected',
        message: 'Account "admin@target.com" had 7 failed login attempts in 10 minutes (threshold: 5). Possible brute-force attack.',
        user_email: 'admin@target.com', trigger_value: 7, trigger_threshold: 5,
        metadata: { failed_count: 7, window_minutes: 10, recommended_action: 'Lock the account immediately.' }
      },
      {
        alert_type: 'HIGH_RISK_PHISHING_SCAN', severity: 'Critical',
        title: '⚠️ High-Risk Phishing URL Detected',
        message: 'URL "http://paypal-verify-signin.security-login.tk" scored 97% risk (threshold: 80%). Verdict: Malicious.',
        user_email: user?.email ?? 'operator@cybershield.ai', trigger_value: 97, trigger_threshold: 80,
        metadata: { target: 'http://paypal-verify-signin.security-login.tk', confidence_score: 97, scan_type: 'URL' }
      },
      {
        alert_type: 'REPEATED_SUSPICIOUS_ACTIVITY', severity: 'High',
        title: '🔁 Repeated Suspicious Activity',
        message: `User "${user?.email ?? 'operator@cybershield.ai'}" triggered 4 suspicious scan results in 15 minutes (threshold: 3).`,
        user_email: user?.email ?? 'operator@cybershield.ai', trigger_value: 4, trigger_threshold: 3,
        metadata: { suspicious_count: 4, window_minutes: 15 }
      },
      {
        alert_type: 'HIGH_RISK_PHISHING_SCAN', severity: 'High',
        title: '⚠️ High-Risk Phishing Email Detected',
        message: 'Email content scored 88% risk. Urgency pressure, credential harvesting, and account threat signals triggered.',
        user_email: user?.email ?? null, trigger_value: 88, trigger_threshold: 80,
        metadata: { confidence_score: 88, scan_type: 'Email', signals: ['urgency', 'credentials', 'account_threat'] }
      },
    ];

    for (const d of demos) {
      await fireAlert(d);
      await new Promise(r => setTimeout(r, 300));
    }
    setGenerating(false);
    load();
  };

  // Filter
  const filtered = alerts.filter(a => {
    if (filterSev !== 'All' && a.severity !== filterSev) return false;
    if (filterType !== 'All' && a.alert_type !== filterType) return false;
    if (filterRead === 'Unread' && a.is_read) return false;
    if (filterRead === 'Read' && !a.is_read) return false;
    return true;
  });

  const unreadCount = alerts.filter(a => !a.is_read).length;

  // Stats
  const stats = {
    total: alerts.length,
    unread: unreadCount,
    critical: alerts.filter(a => a.severity === 'Critical').length,
    high: alerts.filter(a => a.severity === 'High').length,
    medium: alerts.filter(a => a.severity === 'Medium').length,
    low: alerts.filter(a => a.severity === 'Low').length,
  };

  return (
    <div className="dashboard-container">

      {/* Header */}
      <header className="dashboard-header">
        <div className="dashboard-title-area">
          <h1 style={{ display: 'flex', alignItems: 'center', gap: '0.75rem' }}>
            <Bell size={28} style={{ color: unreadCount > 0 ? 'var(--danger)' : 'var(--primary)' }}/>
            Alert Engine
            {unreadCount > 0 && (
              <span style={{ background: 'var(--danger)', color: 'white', borderRadius: '999px', padding: '0.15rem 0.55rem', fontSize: '0.8rem', fontWeight: 800 }}>
                {unreadCount} new
              </span>
            )}
          </h1>
          <p className="auth-subtitle">Real-time security alerts — failed logins, phishing risk, suspicious patterns</p>
        </div>
        <div style={{ display: 'flex', gap: '0.6rem', flexWrap: 'wrap', alignItems: 'center' }}>
          <div onClick={() => setLiveMode(p => !p)} style={{ cursor: 'pointer', padding: '0.35rem 0.75rem', borderRadius: '20px', display: 'flex', alignItems: 'center', gap: '0.35rem',
            background: liveMode ? 'rgba(16,185,129,0.1)' : 'rgba(107,114,128,0.1)',
            border: `1px solid ${liveMode ? 'rgba(16,185,129,0.3)' : 'rgba(107,114,128,0.3)'}`,
            color: liveMode ? 'var(--success)' : 'var(--text-muted)', fontSize: '0.8rem', fontWeight: 600 }}>
            <Radio size={12}/> {liveMode ? 'LIVE' : 'PAUSED'}
          </div>
          <button className="btn btn-secondary btn-small" onClick={load} disabled={loading}>
            <RefreshCw size={13} className={loading ? 'spin' : ''}/>
          </button>
          <button className="btn btn-secondary btn-small" onClick={handleMarkAllRead} disabled={unreadCount === 0}>
            <CheckCheck size={13}/> Mark All Read
          </button>
          {role === 'Admin' && (
            <button className="btn btn-primary btn-small" onClick={generateDemos} disabled={generating}>
              <Zap size={13}/> {generating ? 'Generating...' : 'Generate Demo Alerts'}
            </button>
          )}
        </div>
      </header>

      {/* Action message */}
      {actionMsg && (
        <div className="alert alert-success" style={{ marginBottom: '1rem' }}>{actionMsg}</div>
      )}

      {/* Stats Row */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(120px, 1fr))', gap: '1rem', marginBottom: '1.5rem' }}>
        {[
          { label: 'Total Alerts', val: stats.total, color: 'var(--text-primary)' },
          { label: 'Unread', val: stats.unread, color: stats.unread > 0 ? 'var(--danger)' : 'var(--success)' },
          { label: 'Critical', val: stats.critical, color: 'var(--danger)' },
          { label: 'High', val: stats.high, color: '#f97316' },
          { label: 'Medium', val: stats.medium, color: 'var(--warning)' },
          { label: 'Low', val: stats.low, color: 'var(--success)' },
        ].map(s => (
          <div key={s.label} className="card" style={{ padding: '0.85rem', textAlign: 'center' }}>
            <div style={{ fontSize: '1.5rem', fontWeight: 800, color: s.color, lineHeight: 1 }}>{loading ? '…' : s.val}</div>
            <div style={{ fontSize: '0.7rem', color: 'var(--text-secondary)', marginTop: '0.25rem', textTransform: 'uppercase', letterSpacing: '0.05em' }}>{s.label}</div>
          </div>
        ))}
      </div>

      {/* Main panel */}
      <div style={{ display: 'grid', gridTemplateColumns: selected ? '1fr 400px' : '1fr', gap: '1.5rem', alignItems: 'start' }}>

        {/* Alert List */}
        <div className="card" style={{ padding: 0, overflow: 'hidden' }}>

          {/* Filter Bar */}
          <div style={{ padding: '0.85rem 1.25rem', borderBottom: '1px solid var(--border-color)', display: 'flex', gap: '0.5rem', flexWrap: 'wrap', alignItems: 'center' }}>
            <Filter size={13} style={{ color: 'var(--text-secondary)' }}/>
            {(['All', 'Critical', 'High', 'Medium', 'Low'] as const).map(s => (
              <button key={s} onClick={() => setFilterSev(s)}
                className={`btn btn-small ${filterSev === s ? 'btn-primary' : 'btn-secondary'}`}
                style={{ padding: '0.18rem 0.55rem', fontSize: '0.73rem', height: 'auto' }}>
                {s}
              </button>
            ))}
            <div style={{ width: '1px', height: '18px', background: 'var(--border-color)' }}/>
            {(['All', 'Unread', 'Read'] as const).map(s => (
              <button key={s} onClick={() => setFilterRead(s)}
                className={`btn btn-small ${filterRead === s ? 'btn-primary' : 'btn-secondary'}`}
                style={{ padding: '0.18rem 0.55rem', fontSize: '0.73rem', height: 'auto' }}>
                {s}
              </button>
            ))}
            <span style={{ marginLeft: 'auto', fontSize: '0.75rem', color: 'var(--text-muted)' }}>{filtered.length} alerts</span>
          </div>

          {/* Alert Rows */}
          {loading ? (
            <div style={{ padding: '2rem' }}>
              <div className="skeleton skeleton-title" style={{ width: '180px' }}></div>
              <div style={{ display: 'flex', flexDirection: 'column', gap: '0.75rem' }}>
                <div className="skeleton skeleton-text" style={{ width: '100%', height: '48px' }}></div>
                <div className="skeleton skeleton-text" style={{ width: '100%', height: '48px' }}></div>
                <div className="skeleton skeleton-text" style={{ width: '100%', height: '48px' }}></div>
              </div>
            </div>
          ) : filtered.length === 0 ? (
            <div style={{ padding: '3rem', textAlign: 'center' }}>
              <BellOff size={36} style={{ color: 'var(--text-muted)', display: 'block', margin: '0 auto 0.75rem' }}/>
              <p style={{ color: 'var(--text-secondary)' }}>
                {alerts.length === 0 ? 'No alerts yet. Alerts are generated automatically when threats are detected.' : 'No alerts match your current filters.'}
              </p>
              {role === 'Admin' && alerts.length === 0 && (
                <button className="btn btn-primary btn-small" style={{ margin: '0.75rem auto 0', display: 'inline-flex' }} onClick={generateDemos} disabled={generating}>
                  <Zap size={13}/> Generate Demo Alerts
                </button>
              )}
            </div>
          ) : (
            <div>
              {filtered.map(alert => {
                const s = SEV_CONFIG[alert.severity];
                return (
                  <div key={alert.id} onClick={() => handleRead(alert)}
                    style={{
                      display: 'flex', alignItems: 'flex-start', gap: '0.85rem', padding: '0.9rem 1.25rem',
                      borderBottom: '1px solid var(--border-color)', cursor: 'pointer',
                      background: selected?.id === alert.id ? 'rgba(99,102,241,0.06)' : alert.is_read ? 'transparent' : s.bg,
                      borderLeft: `4px solid ${alert.is_read ? 'transparent' : s.color}`,
                      transition: 'background 0.15s',
                    }}>
                    {/* Severity icon */}
                    <div style={{ width: '32px', height: '32px', borderRadius: '8px', background: s.bg, border: `1px solid ${s.border}`, display: 'flex', alignItems: 'center', justifyContent: 'center', color: s.color, flexShrink: 0 }}>
                      {s.icon}
                    </div>

                    {/* Content */}
                    <div style={{ flex: 1, minWidth: 0 }}>
                      <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', marginBottom: '0.2rem', flexWrap: 'wrap' }}>
                        <span style={{ fontWeight: alert.is_read ? 500 : 700, fontSize: '0.88rem' }}>{alert.title}</span>
                        {!alert.is_read && <span style={{ width: '7px', height: '7px', borderRadius: '50%', background: s.color, display: 'inline-block', flexShrink: 0 }}/>}
                      </div>
                      <p style={{ fontSize: '0.8rem', color: 'var(--text-secondary)', margin: 0, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                        {alert.message}
                      </p>
                      <div style={{ display: 'flex', gap: '0.5rem', marginTop: '0.35rem', alignItems: 'center', flexWrap: 'wrap' }}>
                        <span style={{ fontSize: '0.7rem', fontWeight: 700, color: s.color, textTransform: 'uppercase', letterSpacing: '0.04em' }}>{alert.severity}</span>
                        <span style={{ fontSize: '0.7rem', color: 'var(--text-muted)' }}>•</span>
                        <span style={{ fontSize: '0.7rem', color: 'var(--text-muted)' }}>{TYPE_LABELS[alert.alert_type] ?? alert.alert_type}</span>
                        {alert.trigger_value != null && (
                          <>
                            <span style={{ fontSize: '0.7rem', color: 'var(--text-muted)' }}>•</span>
                            <span style={{ fontSize: '0.7rem', color: 'var(--text-muted)', fontFamily: 'var(--font-mono)' }}>
                              Score: {alert.trigger_value} / {alert.trigger_threshold}
                            </span>
                          </>
                        )}
                        <span style={{ fontSize: '0.7rem', color: 'var(--text-muted)', marginLeft: 'auto', display: 'flex', alignItems: 'center', gap: '2px' }}>
                          <Clock size={10}/>{timeAgo(alert.created_at)}
                        </span>
                      </div>
                    </div>

                    {/* Dismiss */}
                    <button onClick={e => handleDismiss(alert.id, e)} title="Dismiss"
                      style={{ background: 'none', border: 'none', cursor: 'pointer', color: 'var(--text-muted)', padding: '0.2rem', flexShrink: 0, opacity: 0.6 }}
                      onMouseEnter={e => (e.currentTarget.style.opacity = '1')}
                      onMouseLeave={e => (e.currentTarget.style.opacity = '0.6')}>
                      <X size={14}/>
                    </button>
                  </div>
                );
              })}
            </div>
          )}
        </div>

        {/* Detail Panel */}
        {selected && (() => {
          const s = SEV_CONFIG[selected.severity];
          return (
            <div className="card" style={{ position: 'sticky', top: '1rem', border: `1px solid ${s.border}` }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: '1rem' }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: '0.6rem' }}>
                  <div style={{ width: '38px', height: '38px', borderRadius: '9px', background: s.bg, display: 'flex', alignItems: 'center', justifyContent: 'center', color: s.color }}>
                    {s.icon}
                  </div>
                  <div>
                    <div style={{ fontWeight: 700, fontSize: '0.88rem' }}>{TYPE_LABELS[selected.alert_type]}</div>
                    <div style={{ fontSize: '0.75rem', color: s.color, fontWeight: 600 }}>{selected.severity} Severity</div>
                  </div>
                </div>
                <button onClick={() => setSelected(null)} className="btn btn-secondary btn-small" style={{ padding: '0.2rem 0.4rem', height: 'auto' }}>
                  <X size={13}/>
                </button>
              </div>

              <div style={{ display: 'flex', flexDirection: 'column', gap: '0.75rem', fontSize: '0.84rem' }}>

                {/* Alert message */}
                <div style={{ background: 'var(--bg-primary)', borderRadius: 'var(--radius-md)', padding: '0.75rem', lineHeight: 1.7 }}>
                  <div style={{ fontSize: '0.68rem', textTransform: 'uppercase', letterSpacing: '0.05em', color: 'var(--text-muted)', marginBottom: '0.3rem', fontWeight: 700 }}>Alert Message</div>
                  {selected.message}
                </div>

                {/* Trigger metric */}
                {selected.trigger_value != null && (
                  <div style={{ background: s.bg, border: `1px solid ${s.border}`, borderRadius: 'var(--radius-md)', padding: '0.75rem' }}>
                    <div style={{ fontSize: '0.68rem', textTransform: 'uppercase', letterSpacing: '0.05em', color: s.color, marginBottom: '0.4rem', fontWeight: 700 }}>
                      Trigger Metric
                    </div>
                    <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem' }}>
                      <div style={{ flex: 1, background: 'var(--bg-primary)', borderRadius: '6px', height: '8px', overflow: 'hidden' }}>
                        <div style={{ width: `${Math.min(100, ((selected.trigger_value ?? 0) / (selected.trigger_threshold ?? 100)) * 100)}%`, height: '100%', background: s.color, borderRadius: '6px', transition: 'width 0.6s ease' }}/>
                      </div>
                      <span style={{ fontFamily: 'var(--font-mono)', fontWeight: 700, color: s.color, fontSize: '0.88rem', whiteSpace: 'nowrap' }}>
                        {selected.trigger_value} / {selected.trigger_threshold}
                      </span>
                    </div>
                    <div style={{ fontSize: '0.73rem', color: 'var(--text-muted)', marginTop: '0.3rem' }}>
                      {Math.round(((selected.trigger_value ?? 0) / (selected.trigger_threshold ?? 100)) * 100)}% of threshold exceeded
                    </div>
                  </div>
                )}

                {/* Meta grid */}
                <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '0.5rem' }}>
                  {[
                    { label: 'Time', val: new Date(selected.created_at).toLocaleString() },
                    { label: 'Status', val: selected.is_read ? '👁 Viewed' : '🔴 Unread' },
                    { label: 'User', val: selected.user_email ?? '—' },
                    { label: 'Alert Type', val: TYPE_LABELS[selected.alert_type] ?? selected.alert_type },
                  ].map(f => (
                    <div key={f.label} style={{ background: 'var(--bg-primary)', borderRadius: '6px', padding: '0.5rem 0.6rem' }}>
                      <div style={{ fontSize: '0.67rem', color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.05em', marginBottom: '0.15rem' }}>{f.label}</div>
                      <div style={{ fontFamily: 'var(--font-mono)', fontSize: '0.76rem', wordBreak: 'break-all' }}>{f.val}</div>
                    </div>
                  ))}
                </div>

                {/* Recommended action from metadata */}
                {selected.metadata?.recommended_action && (
                  <div style={{ background: 'rgba(59,130,246,0.08)', border: '1px solid rgba(59,130,246,0.2)', borderRadius: 'var(--radius-md)', padding: '0.75rem' }}>
                    <div style={{ fontSize: '0.68rem', textTransform: 'uppercase', letterSpacing: '0.05em', color: '#3b82f6', marginBottom: '0.35rem', fontWeight: 700, display: 'flex', alignItems: 'center', gap: '0.3rem' }}>
                      <Eye size={11}/> Recommended Action
                    </div>
                    <div style={{ fontSize: '0.82rem', lineHeight: 1.7 }}>
                      {selected.metadata.recommended_action}
                    </div>
                  </div>
                )}

                {/* Raw metadata */}
                {Object.keys(selected.metadata ?? {}).length > 0 && (
                  <details style={{ fontSize: '0.8rem' }}>
                    <summary style={{ cursor: 'pointer', color: 'var(--text-secondary)', marginBottom: '0.4rem' }}>Raw Metadata</summary>
                    <pre style={{ background: 'var(--bg-primary)', border: '1px solid var(--border-color)', borderRadius: '6px', padding: '0.6rem', fontSize: '0.72rem', fontFamily: 'var(--font-mono)', color: 'var(--text-secondary)', overflowX: 'auto', maxHeight: '150px', overflowY: 'auto', margin: 0 }}>
                      {JSON.stringify(selected.metadata, null, 2)}
                    </pre>
                  </details>
                )}

                {/* Dismiss */}
                <button className="btn btn-secondary" onClick={() => handleDismiss(selected.id)}
                  style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', gap: '0.5rem', marginTop: '0.25rem' }}>
                  <Trash2 size={14}/> Dismiss Alert
                </button>
              </div>
            </div>
          );
        })()}
      </div>
    </div>
  );
};

export default AlertsPage;
