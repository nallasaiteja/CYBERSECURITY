import React, { useEffect, useState } from 'react';
import { supabase } from '../supabaseClient';
import { useAuth } from '../contexts/AuthContext';
import { 
  PlusCircle, 
  Trash2, 
  RefreshCw, 
  ShieldCheck,
  Users,
  CheckCircle2,
  Clock,
  Search,
  Download,
  AlertTriangle,
  Globe,
  Mail,
  MessageSquare,
  Skull,
  Lock,
  Unlock,
  Activity,
  FileText,
  FileSpreadsheet
} from 'lucide-react';

interface Profile {
  id: string;
  email: string;
  role: 'Admin' | 'User';
  is_suspended: boolean;
  created_at: string;
}

interface PhishingScan {
  id: string;
  target_url: string;
  result: 'Clean' | 'Suspicious' | 'Malicious';
  confidence_score: number;
  scan_type: 'URL' | 'Email' | 'SMS';
  content_snippet?: string;
  scanned_at: string;
}

interface ThreatLog {
  id: string;
  event_type: string;
  severity: 'Low' | 'Medium' | 'High' | 'Critical';
  description: string;
  user_email?: string;
  ip_address?: string;
  resolved: boolean;
  created_at: string;
  metadata?: any;
}



interface ThreatAlert {
  id: string;
  title: string;
  severity: 'Low' | 'Medium' | 'High' | 'Critical';
  source_ip: string;
  status: 'Active' | 'Investigating' | 'Resolved';
  created_at: string;
}

export const AdminPanel: React.FC = () => {
  const { user } = useAuth();
  const [activeTab, setActiveTab] = useState<'operators' | 'scans' | 'threats' | 'register' | 'exporter'>('operators');
  
  // Data States
  const [profiles, setProfiles] = useState<Profile[]>([]);
  const [scans, setScans] = useState<PhishingScan[]>([]);
  const [threatLogs, setThreatLogs] = useState<ThreatLog[]>([]);
  const [threatAlerts, setThreatAlerts] = useState<ThreatAlert[]>([]);
  
  // Loading States
  const [loading, setLoading] = useState(true);
  const [actionLoading, setActionLoading] = useState<string | null>(null);
  
  // Filters & Search
  const [searchTerm, setSearchTerm] = useState('');
  const [filterRole, setFilterRole] = useState<'All' | 'Admin' | 'User'>('All');
  const [filterSuspended, setFilterSuspended] = useState<'All' | 'Active' | 'Suspended'>('All');
  const [filterScanType, setFilterScanType] = useState<'All' | 'URL' | 'Email' | 'SMS'>('All');
  const [filterScanResult, setFilterScanResult] = useState<'All' | 'Clean' | 'Suspicious' | 'Malicious'>('All');
  const [filterSeverity, setFilterSeverity] = useState<'All' | 'Low' | 'Medium' | 'High' | 'Critical'>('All');

  // Legacy Threat Register Form
  const [newTitle, setNewTitle] = useState('');
  const [newSeverity, setNewSeverity] = useState<'Low' | 'Medium' | 'High' | 'Critical'>('Medium');
  const [newSourceIP, setNewSourceIP] = useState('');
  const [formLoading, setFormLoading] = useState(false);
  const [formMessage, setFormMessage] = useState<{ type: 'success' | 'error', text: string } | null>(null);

  const fetchData = async () => {
    try {
      setLoading(true);
      
      // Fetch Profiles
      const { data: profileData, error: profileErr } = await supabase
        .from('profiles')
        .select('*')
        .order('created_at', { ascending: false });
      if (profileErr) throw profileErr;
      setProfiles(profileData || []);

      // Fetch Phishing Scans
      const { data: scanData, error: scanErr } = await supabase
        .from('phishing_scans')
        .select('*')
        .order('scanned_at', { ascending: false });
      if (scanErr) throw scanErr;
      setScans(scanData || []);

      // Fetch Threat Logs
      const { data: logData, error: logErr } = await supabase
        .from('threat_logs')
        .select('*')
        .order('created_at', { ascending: false });
      if (logErr) throw logErr;
      setThreatLogs(logData || []);



      // Fetch Legacy Threat Alerts
      const { data: threatAlertData, error: threatAlertErr } = await supabase
        .from('threat_alerts')
        .select('*')
        .order('created_at', { ascending: false });
      if (threatAlertErr) throw threatAlertErr;
      setThreatAlerts(threatAlertData || []);

    } catch (err: any) {
      console.error('Database retrieval failed:', err.message);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchData();
  }, []);

  // Action: Toggle User Suspension
  const handleToggleSuspension = async (profileId: string, currentStatus: boolean) => {
    if (profileId === user?.id) {
      alert("Security Violation: You cannot suspend your own active administrator profile.");
      return;
    }

    setActionLoading(profileId);
    try {
      const { error } = await supabase
        .from('profiles')
        .update({ is_suspended: !currentStatus })
        .eq('id', profileId);

      if (error) throw error;
      
      // Update local state
      setProfiles(prev => prev.map(p => p.id === profileId ? { ...p, is_suspended: !currentStatus } : p));
      
      // Log admin action
      await supabase.from('threat_logs').insert([{
        event_type: 'ADMIN_ACTION',
        severity: 'Medium',
        description: `Admin suspended/unsuspended operator profile: ${profileId}`,
        user_email: user?.email,
        metadata: { target_profile_id: profileId, suspended: !currentStatus }
      }]);

    } catch (err: any) {
      alert(`Deactivation toggle failed: ${err.message}`);
    } finally {
      setActionLoading(null);
    }
  };

  // Action: Delete Operator Account (RPC)
  const handleDeleteOperator = async (profileId: string, email: string) => {
    if (profileId === user?.id) {
      alert("Security Violation: You cannot purge your own active administrator profile.");
      return;
    }

    const firstConfirm = confirm(`[CRITICAL ACTION] Are you absolutely sure you want to delete the operator account: ${email}? This action cannot be undone.`);
    if (!firstConfirm) return;

    const secondConfirm = confirm(`[DOUBLE CONFIRMATION] Please verify: all credentials, threat history, and dashboard configurations associated with ${email} will be permanently destroyed. Confirm delete?`);
    if (!secondConfirm) return;

    setActionLoading(profileId);
    try {
      const { error } = await supabase.rpc('delete_user', { target_user_id: profileId });
      if (error) throw error;

      // Update local state
      setProfiles(prev => prev.filter(p => p.id !== profileId));

      // Log admin action
      await supabase.from('threat_logs').insert([{
        event_type: 'ADMIN_ACTION',
        severity: 'High',
        description: `Admin deleted operator account: ${email}`,
        user_email: user?.email,
        metadata: { target_profile_id: profileId, target_email: email }
      }]);

      alert(`Operator account ${email} has been successfully purged from security credentials.`);
    } catch (err: any) {
      alert(`Operator deletion failed: ${err.message}`);
    } finally {
      setActionLoading(null);
    }
  };

  // Action: Toggle Threat Log Resolved Status
  const handleToggleLogResolved = async (logId: string, currentStatus: boolean) => {
    try {
      const { error } = await supabase
        .from('threat_logs')
        .update({ resolved: !currentStatus })
        .eq('id', logId);

      if (error) throw error;

      setThreatLogs(prev => prev.map(l => l.id === logId ? { ...l, resolved: !currentStatus } : l));
    } catch (err: any) {
      alert(`Failed to resolve incident: ${err.message}`);
    }
  };



  // Action: Create Legacy Threat Alert
  const handleCreateThreatAlert = async (e: React.FormEvent) => {
    e.preventDefault();
    setFormLoading(true);
    setFormMessage(null);

    const ipPattern = /^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$/;
    if (!ipPattern.test(newSourceIP)) {
      setFormMessage({ type: 'error', text: 'Please input a valid IPv4 source address.' });
      setFormLoading(false);
      return;
    }

    try {
      const { error } = await supabase
        .from('threat_alerts')
        .insert([{ title: newTitle, severity: newSeverity, source_ip: newSourceIP, status: 'Active' }]);

      if (error) throw error;

      setFormMessage({ type: 'success', text: 'Security threat alert successfully registered!' });
      setNewTitle('');
      setNewSourceIP('');
      
      // Refresh legacy alerts
      const { data } = await supabase.from('threat_alerts').select('*').order('created_at', { ascending: false });
      setThreatAlerts(data || []);
    } catch (err: any) {
      setFormMessage({ type: 'error', text: err.message || 'Database insert transaction failed.' });
    } finally {
      setFormLoading(false);
    }
  };

  // Action: Cycle Legacy Threat Status
  const handleUpdateThreatStatus = async (id: string, currentStatus: string) => {
    let nextStatus: 'Active' | 'Investigating' | 'Resolved' = 'Investigating';
    if (currentStatus === 'Active') nextStatus = 'Investigating';
    else if (currentStatus === 'Investigating') nextStatus = 'Resolved';
    else nextStatus = 'Active';

    try {
      const { error } = await supabase
        .from('threat_alerts')
        .update({ status: nextStatus })
        .eq('id', id);

      if (error) throw error;
      
      // Update local state
      setThreatAlerts(prev => prev.map(t => t.id === id ? { ...t, status: nextStatus } : t));
    } catch (err: any) {
      alert(`Status update failed: ${err.message}`);
    }
  };

  // Action: Delete Legacy Threat Alert
  const handleDeleteThreatAlert = async (id: string) => {
    if (!confirm('Are you sure you want to purge this threat event record?')) return;
    try {
      const { error } = await supabase
        .from('threat_alerts')
        .delete()
        .eq('id', id);

      if (error) throw error;
      setThreatAlerts(prev => prev.filter(t => t.id !== id));
    } catch (err: any) {
      alert(`Deletion failed: ${err.message}`);
    }
  };

  // CSV Export Utility
  const downloadCSV = (data: any[], filename: string) => {
    if (data.length === 0) {
      alert("No database records available to export.");
      return;
    }
    const headers = Object.keys(data[0]);
    const rows = data.map(row => 
      headers.map(header => {
        const val = row[header];
        const stringVal = typeof val === 'object' ? JSON.stringify(val) : String(val ?? '');
        return `"${stringVal.replace(/"/g, '""')}"`;
      }).join(',')
    );
    const csvContent = [headers.join(','), ...rows].join('\n');
    const blob = new Blob([csvContent], { type: 'text/csv;charset=utf-8;' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.setAttribute('href', url);
    link.setAttribute('download', `${filename}.csv`);
    link.style.visibility = 'hidden';
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
  };

  // JSON Export Utility
  const downloadJSON = (data: any[], filename: string) => {
    if (data.length === 0) {
      alert("No database records available to export.");
      return;
    }
    const jsonContent = JSON.stringify(data, null, 2);
    const blob = new Blob([jsonContent], { type: 'application/json;charset=utf-8;' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.setAttribute('href', url);
    link.setAttribute('download', `${filename}.json`);
    link.style.visibility = 'hidden';
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
  };

  // Filtered operators
  const filteredProfiles = profiles.filter(p => {
    const matchesSearch = p.email.toLowerCase().includes(searchTerm.toLowerCase()) || p.id.includes(searchTerm);
    const matchesRole = filterRole === 'All' || p.role === filterRole;
    const matchesSuspended = filterSuspended === 'All' || 
      (filterSuspended === 'Suspended' && p.is_suspended) || 
      (filterSuspended === 'Active' && !p.is_suspended);
    return matchesSearch && matchesRole && matchesSuspended;
  });

  // Filtered scans
  const filteredScans = scans.filter(s => {
    const matchesSearch = s.target_url.toLowerCase().includes(searchTerm.toLowerCase()) || s.id.includes(searchTerm);
    const matchesType = filterScanType === 'All' || s.scan_type === filterScanType;
    const matchesResult = filterScanResult === 'All' || s.result === filterScanResult;
    return matchesSearch && matchesType && matchesResult;
  });

  // Filtered threat logs
  const filteredThreatLogs = threatLogs.filter(l => {
    const matchesSearch = l.description.toLowerCase().includes(searchTerm.toLowerCase()) || 
      l.event_type.toLowerCase().includes(searchTerm.toLowerCase()) ||
      (l.user_email && l.user_email.toLowerCase().includes(searchTerm.toLowerCase()));
    const matchesSeverity = filterSeverity === 'All' || l.severity === filterSeverity;
    return matchesSearch && matchesSeverity;
  });



  // Legacy alerts
  const filteredThreatAlerts = threatAlerts.filter(ta => {
    return ta.title.toLowerCase().includes(searchTerm.toLowerCase()) || ta.source_ip.includes(searchTerm);
  });

  return (
    <div className="admin-panel-container">
      <header className="dashboard-header">
        <div className="dashboard-title-area">
          <h1 style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
            <ShieldCheck size={28} style={{ color: 'var(--primary)' }} />
            Security Administration Hub
          </h1>
          <p className="auth-subtitle">Role-based controls, logs audit, and system compliance exporter</p>
        </div>
        <button 
          className="btn btn-secondary btn-small" 
          onClick={fetchData}
          disabled={loading}
        >
          <RefreshCw size={14} className={loading ? 'spin' : ''} />
          Reload Database
        </button>
      </header>

      {/* Tabs navigation */}
      <div className="admin-tabs-nav" style={{ display: 'flex', gap: '0.5rem', marginBottom: '1.5rem', flexWrap: 'wrap', borderBottom: '1px solid var(--border-color)', paddingBottom: '0.75rem' }}>
        {[
          { id: 'operators', label: 'Operators Directory', icon: <Users size={16} /> },
          { id: 'scans', label: 'Phishing Scans', icon: <Globe size={16} /> },
          { id: 'threats', label: 'Threat Incident Logs', icon: <Activity size={16} /> },
          { id: 'register', label: 'Threat Register', icon: <AlertTriangle size={16} /> },
          { id: 'exporter', label: 'Reports Exporter', icon: <FileSpreadsheet size={16} /> },
        ].map(tab => (
          <button
            key={tab.id}
            className={`btn btn-small ${activeTab === tab.id ? 'btn-primary' : 'btn-secondary'}`}
            style={{ display: 'flex', alignItems: 'center', gap: '0.4rem', borderRadius: '6px' }}
            onClick={() => {
              setActiveTab(tab.id as any);
              setSearchTerm('');
            }}
          >
            {tab.icon}
            {tab.label}
          </button>
        ))}
      </div>

      {/* Search & filters header bar (omitted for exporter tab) */}
      {activeTab !== 'exporter' && (
        <div className="card" style={{ padding: '1rem', marginBottom: '1.5rem', display: 'flex', gap: '1rem', flexWrap: 'wrap', alignItems: 'center' }}>
          <div className="input-wrapper" style={{ flex: '1 1 300px', marginBottom: 0 }}>
            <Search className="input-icon" size={16} />
            <input
              type="text"
              className="form-input"
              style={{ paddingLeft: '2.5rem', height: '38px' }}
              placeholder={`Search in ${activeTab === 'operators' ? 'operators' : activeTab === 'scans' ? 'scans' : activeTab === 'threats' ? 'threat logs' : activeTab === 'alerts' ? 'alerts' : 'register'}...`}
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
            />
          </div>

          {/* Dynamic Filters */}
          {activeTab === 'operators' && (
            <div style={{ display: 'flex', gap: '0.5rem' }}>
              <select className="form-input" style={{ width: '120px', height: '38px', padding: '0 0.5rem 0 1rem' }} value={filterRole} onChange={(e) => setFilterRole(e.target.value as any)}>
                <option value="All">All Roles</option>
                <option value="Admin">Admin</option>
                <option value="User">User</option>
              </select>
              <select className="form-input" style={{ width: '150px', height: '38px', padding: '0 0.5rem 0 1rem' }} value={filterSuspended} onChange={(e) => setFilterSuspended(e.target.value as any)}>
                <option value="All">All Statuses</option>
                <option value="Active">Active Only</option>
                <option value="Suspended">Suspended Only</option>
              </select>
            </div>
          )}

          {activeTab === 'scans' && (
            <div style={{ display: 'flex', gap: '0.5rem' }}>
              <select className="form-input" style={{ width: '130px', height: '38px', padding: '0 0.5rem 0 1rem' }} value={filterScanType} onChange={(e) => setFilterScanType(e.target.value as any)}>
                <option value="All">All Types</option>
                <option value="URL">URL</option>
                <option value="Email">Email</option>
                <option value="SMS">SMS</option>
              </select>
              <select className="form-input" style={{ width: '150px', height: '38px', padding: '0 0.5rem 0 1rem' }} value={filterScanResult} onChange={(e) => setFilterScanResult(e.target.value as any)}>
                <option value="All">All Verdicts</option>
                <option value="Clean">Clean</option>
                <option value="Suspicious">Suspicious</option>
                <option value="Malicious">Malicious</option>
              </select>
            </div>
          )}

          {(activeTab === 'threats' || activeTab === 'alerts') && (
            <div style={{ display: 'flex', gap: '0.5rem' }}>
              <select className="form-input" style={{ width: '150px', height: '38px', padding: '0 0.5rem 0 1rem' }} value={filterSeverity} onChange={(e) => setFilterSeverity(e.target.value as any)}>
                <option value="All">All Severities</option>
                <option value="Low">Low</option>
                <option value="Medium">Medium</option>
                <option value="High">High</option>
                <option value="Critical">Critical</option>
              </select>
            </div>
          )}
        </div>
      )}

      {/* Main Workspace content based on activeTab */}
      {loading ? (
        <div className="card" style={{ padding: '2rem' }}>
          <div className="skeleton skeleton-title" style={{ width: '220px' }}></div>
          <div style={{ display: 'flex', flexDirection: 'column', gap: '0.75rem', marginTop: '1rem' }}>
            <div className="skeleton skeleton-text" style={{ width: '100%', height: '40px' }}></div>
            <div className="skeleton skeleton-text" style={{ width: '100%', height: '40px' }}></div>
            <div className="skeleton skeleton-text" style={{ width: '100%', height: '40px' }}></div>
          </div>
        </div>
      ) : (
        <div className="admin-workspace-content">

          {/* TAB 1: OPERATORS DIRECTORY */}
          {activeTab === 'operators' && (
            <div className="card" style={{ padding: 0, overflow: 'hidden' }}>
              <div className="metric-card-header" style={{ padding: '1.25rem' }}>
                <h2 style={{ fontSize: '1.1rem', display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                  <Users size={18} style={{ color: 'var(--primary)' }} />
                  Operators Registry Directory ({filteredProfiles.length})
                </h2>
              </div>
              
              <div className="table-responsive">
                <table className="cyber-table">
                  <thead>
                    <tr>
                      <th>Operator ID</th>
                      <th>Email Identifier</th>
                      <th>Access Clearance</th>
                      <th>Operational Status</th>
                      <th>Creation Sequence</th>
                      <th style={{ textAlign: 'right' }}>Security Actions</th>
                    </tr>
                  </thead>
                  <tbody>
                    {filteredProfiles.length === 0 ? (
                      <tr>
                        <td colSpan={6} style={{ textAlign: 'center', color: 'var(--text-secondary)' }}>No registered identities found matching criteria.</td>
                      </tr>
                    ) : (
                      filteredProfiles.map(p => (
                        <tr key={p.id} style={{ opacity: p.is_suspended ? 0.6 : 1 }}>
                          <td style={{ fontFamily: 'var(--font-mono)', fontSize: '0.8rem' }}>{p.id}</td>
                          <td style={{ fontWeight: 600 }}>{p.email} {p.id === user?.id && <span style={{ color: 'var(--primary)', fontSize: '0.75rem' }}>(You)</span>}</td>
                          <td>
                            <span className="badge" style={{ 
                              backgroundColor: p.role === 'Admin' ? 'var(--primary-glow)' : 'var(--bg-tertiary)',
                              color: p.role === 'Admin' ? 'var(--primary)' : 'var(--text-secondary)'
                            }}>
                              {p.role}
                            </span>
                          </td>
                          <td>
                            {p.is_suspended ? (
                              <span className="badge badge-critical" style={{ display: 'inline-flex', alignItems: 'center', gap: '0.2rem' }}>
                                <Lock size={10} /> Suspended
                              </span>
                            ) : (
                              <span className="badge badge-active" style={{ display: 'inline-flex', alignItems: 'center', gap: '0.2rem' }}>
                                <Unlock size={10} /> Active
                              </span>
                            )}
                          </td>
                          <td style={{ fontSize: '0.8rem', color: 'var(--text-secondary)' }}>
                            {new Date(p.created_at).toLocaleString()}
                          </td>
                          <td style={{ textAlign: 'right' }}>
                            <div style={{ display: 'inline-flex', gap: '0.5rem' }}>
                              <button
                                className={`btn btn-small ${p.is_suspended ? 'btn-primary' : 'btn-secondary'}`}
                                style={{ padding: '0.25rem 0.5rem', width: 'auto', display: 'flex', alignItems: 'center', gap: '0.25rem' }}
                                onClick={() => handleToggleSuspension(p.id, p.is_suspended)}
                                disabled={actionLoading === p.id || p.id === user?.id}
                                title={p.is_suspended ? "Activate Operator" : "Suspend Operator"}
                              >
                                {p.is_suspended ? <Unlock size={12} /> : <Lock size={12} />}
                                {p.is_suspended ? 'Reactivate' : 'Suspend'}
                              </button>
                              <button
                                className="btn btn-danger btn-small"
                                style={{ padding: '0.25rem 0.4rem', width: 'auto' }}
                                onClick={() => handleDeleteOperator(p.id, p.email)}
                                disabled={actionLoading === p.id || p.id === user?.id}
                                title="Purge Account"
                              >
                                <Trash2 size={12} />
                              </button>
                            </div>
                          </td>
                        </tr>
                      ))
                    )}
                  </tbody>
                </table>
              </div>
            </div>
          )}

          {/* TAB 2: PHISHING AUDITS */}
          {activeTab === 'scans' && (
            <div className="card" style={{ padding: 0, overflow: 'hidden' }}>
              <div className="metric-card-header" style={{ padding: '1.25rem' }}>
                <h2 style={{ fontSize: '1.1rem', display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                  <Globe size={18} style={{ color: 'var(--primary)' }} />
                  Phishing Analysis Audit Ledger ({filteredScans.length})
                </h2>
              </div>

              <div className="table-responsive">
                <table className="cyber-table">
                  <thead>
                    <tr>
                      <th style={{ width: '80px' }}>Type</th>
                      <th>Target Value / Scan Content</th>
                      <th style={{ width: '130px' }}>Verdict</th>
                      <th style={{ width: '160px' }}>Confidence Score</th>
                      <th style={{ width: '200px' }}>Analysis Timestamp</th>
                    </tr>
                  </thead>
                  <tbody>
                    {filteredScans.length === 0 ? (
                      <tr>
                        <td colSpan={5} style={{ textAlign: 'center', color: 'var(--text-secondary)' }}>No phishing scan records located.</td>
                      </tr>
                    ) : (
                      filteredScans.map(s => (
                        <tr key={s.id}>
                          <td>
                            <span className="badge" style={{ display: 'inline-flex', alignItems: 'center', gap: '0.2rem' }}>
                              {s.scan_type === 'URL' && <Globe size={10} />}
                              {s.scan_type === 'Email' && <Mail size={10} />}
                              {s.scan_type === 'SMS' && <MessageSquare size={10} />}
                              {s.scan_type ?? 'URL'}
                            </span>
                          </td>
                          <td>
                            <div style={{ wordBreak: 'break-all', fontSize: '0.82rem', maxWidth: '400px' }} title={s.target_url}>
                              {s.target_url}
                            </div>
                            {s.content_snippet && (
                              <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)', fontStyle: 'italic', marginTop: '0.25rem' }}>
                                Snippet: "{s.content_snippet.length > 80 ? s.content_snippet.substring(0, 80) + '...' : s.content_snippet}"
                              </div>
                            )}
                          </td>
                          <td>
                            {s.result === 'Malicious' && <span className="badge badge-critical" style={{ display: 'inline-block', width: '90px', textAlign: 'center' }}>Malicious</span>}
                            {s.result === 'Suspicious' && <span className="badge badge-high" style={{ display: 'inline-block', width: '90px', textAlign: 'center' }}>Suspicious</span>}
                            {s.result === 'Clean' && <span className="badge badge-active" style={{ display: 'inline-block', width: '90px', textAlign: 'center' }}>Clean</span>}
                          </td>
                          <td>
                            <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                              <div style={{ flex: 1, backgroundColor: 'var(--bg-tertiary)', borderRadius: '4px', height: '6px', overflow: 'hidden' }}>
                                <div style={{ 
                                  height: '100%', 
                                  width: `${s.confidence_score}%`, 
                                  backgroundColor: s.result === 'Malicious' ? 'var(--danger)' : s.result === 'Suspicious' ? '#f97316' : 'var(--success)'
                                }} />
                              </div>
                              <span style={{ fontWeight: 'bold', fontSize: '0.8rem', width: '30px' }}>{s.confidence_score}%</span>
                            </div>
                          </td>
                          <td style={{ fontSize: '0.8rem', color: 'var(--text-secondary)' }}>
                            {new Date(s.scanned_at).toLocaleString()}
                          </td>
                        </tr>
                      ))
                    )}
                  </tbody>
                </table>
              </div>
            </div>
          )}

          {/* TAB 3: THREAT INCIDENT LOGS */}
          {activeTab === 'threats' && (
            <div className="card" style={{ padding: 0, overflow: 'hidden' }}>
              <div className="metric-card-header" style={{ padding: '1.25rem' }}>
                <h2 style={{ fontSize: '1.1rem', display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                  <Activity size={18} style={{ color: 'var(--primary)' }} />
                  Threat Incident Logs ledger ({filteredThreatLogs.length})
                </h2>
              </div>

              <div className="table-responsive">
                <table className="cyber-table">
                  <thead>
                    <tr>
                      <th style={{ width: '100px' }}>Severity</th>
                      <th style={{ width: '150px' }}>Event Type</th>
                      <th>Incident Description</th>
                      <th style={{ width: '180px' }}>Origin (User/IP)</th>
                      <th style={{ width: '180px' }}>Timestamp</th>
                      <th style={{ width: '100px', textAlign: 'right' }}>Incident State</th>
                    </tr>
                  </thead>
                  <tbody>
                    {filteredThreatLogs.length === 0 ? (
                      <tr>
                        <td colSpan={6} style={{ textAlign: 'center', color: 'var(--text-secondary)' }}>No incident threat logs located.</td>
                      </tr>
                    ) : (
                      filteredThreatLogs.map(l => (
                        <tr key={l.id} style={{ opacity: l.resolved ? 0.6 : 1 }}>
                          <td>
                            <span style={{ 
                              color: l.severity === 'Critical' ? 'var(--danger)' : l.severity === 'High' ? '#f97316' : l.severity === 'Medium' ? 'var(--warning)' : 'var(--success)',
                              fontWeight: 700,
                              fontSize: '0.82rem',
                              display: 'inline-flex',
                              alignItems: 'center',
                              gap: '0.2rem'
                            }}>
                              {l.severity === 'Critical' && <Skull size={12} />}
                              {l.severity}
                            </span>
                          </td>
                          <td style={{ fontWeight: 600, fontSize: '0.82rem' }}>{l.event_type}</td>
                          <td style={{ fontSize: '0.82rem' }}>{l.description}</td>
                          <td style={{ fontSize: '0.78rem', fontFamily: 'var(--font-mono)' }}>
                            <div>{l.user_email ?? 'System'}</div>
                            <div style={{ color: 'var(--text-muted)', fontSize: '0.72rem' }}>{l.ip_address}</div>
                          </td>
                          <td style={{ fontSize: '0.8rem', color: 'var(--text-secondary)' }}>
                            {new Date(l.created_at).toLocaleString()}
                          </td>
                          <td style={{ textAlign: 'right' }}>
                            <button
                              className={`btn btn-small ${l.resolved ? 'btn-secondary' : 'btn-primary'}`}
                              style={{ padding: '0.25rem 0.5rem', width: '90px' }}
                              onClick={() => handleToggleLogResolved(l.id, l.resolved)}
                            >
                              {l.resolved ? 'Reopen' : 'Resolve'}
                            </button>
                          </td>
                        </tr>
                      ))
                    )}
                  </tbody>
                </table>
              </div>
            </div>
          )}



          {/* TAB 5: LEGACY THREAT REGISTER */}
          {activeTab === 'register' && (
            <div className="admin-card-grid" style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(320px, 1fr))', gap: '1.5rem' }}>
              
              {/* Form to Create Security Alerts */}
              <div className="card">
                <div className="metric-card-header">
                  <h2 style={{ fontSize: '1.2rem', display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                    <PlusCircle size={20} style={{ color: 'var(--primary)' }} />
                    Publish Threat Event
                  </h2>
                </div>

                <form onSubmit={handleCreateThreatAlert} className="admin-form" style={{ marginTop: '1rem' }}>
                  {formMessage && (
                    <div className={`alert ${formMessage.type === 'success' ? 'alert-success' : 'alert-danger'}`}>
                      {formMessage.text}
                    </div>
                  )}

                  <div className="form-group">
                    <label className="form-label" htmlFor="title">Threat Description</label>
                    <input 
                      id="title"
                      type="text" 
                      className="form-input" 
                      placeholder="e.g. Brute Force Attempt"
                      value={newTitle}
                      onChange={(e) => setNewTitle(e.target.value)}
                      required 
                      style={{ paddingLeft: '1rem' }}
                    />
                  </div>

                  <div className="form-group">
                    <label className="form-label" htmlFor="sourceIP">Source IPv4 Address</label>
                    <input 
                      id="sourceIP"
                      type="text" 
                      className="form-input" 
                      placeholder="e.g. 192.168.1.1"
                      value={newSourceIP}
                      onChange={(e) => setNewSourceIP(e.target.value)}
                      required 
                      style={{ paddingLeft: '1rem' }}
                    />
                  </div>

                  <div className="form-group">
                    <label className="form-label" htmlFor="severity">Severity Risk Level</label>
                    <select 
                      id="severity"
                      className="form-input" 
                      value={newSeverity}
                      onChange={(e) => setNewSeverity(e.target.value as any)}
                      style={{ paddingLeft: '1rem' }}
                    >
                      <option value="Low">Low Risk</option>
                      <option value="Medium">Medium Risk</option>
                      <option value="High">High Risk</option>
                      <option value="Critical">Critical Risk</option>
                    </select>
                  </div>

                  <button type="submit" className="btn btn-primary" disabled={formLoading} style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', gap: '0.25rem', marginTop: '1.5rem', width: '100%' }}>
                    <PlusCircle size={16} />
                    {formLoading ? 'Publishing Event...' : 'Publish to Feed'}
                  </button>
                </form>
              </div>

              {/* Threat alerts registry table */}
              <div className="card" style={{ padding: 0, overflow: 'hidden' }}>
                <div className="metric-card-header" style={{ padding: '1.25rem' }}>
                  <h2 style={{ fontSize: '1.2rem', display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                    <AlertTriangle size={20} style={{ color: 'var(--primary)' }} />
                    Active Ledgers Register ({filteredThreatAlerts.length})
                  </h2>
                </div>

                <div className="table-responsive">
                  <table className="cyber-table">
                    <thead>
                      <tr>
                        <th>Event</th>
                        <th>Risk</th>
                        <th>Source IP</th>
                        <th>Status</th>
                        <th style={{ textAlign: 'right' }}>Actions</th>
                      </tr>
                    </thead>
                    <tbody>
                      {filteredThreatAlerts.length === 0 ? (
                        <tr>
                          <td colSpan={5} style={{ textAlign: 'center', color: 'var(--text-secondary)' }}>No ledger threat alerts.</td>
                        </tr>
                      ) : (
                        filteredThreatAlerts.map(alert => (
                          <tr key={alert.id}>
                            <td style={{ fontWeight: '600', fontSize: '0.82rem' }}>{alert.title}</td>
                            <td>
                              <span className={`badge ${
                                alert.severity === 'Critical' ? 'badge-critical' : 
                                alert.severity === 'High' ? 'badge-high' : 
                                alert.severity === 'Medium' ? 'badge-medium' : 'badge-low'
                              }`}>
                                {alert.severity}
                              </span>
                            </td>
                            <td style={{ fontFamily: 'var(--font-mono)', fontSize: '0.78rem' }}>{alert.source_ip}</td>
                            <td>
                              <span className={`badge ${alert.status === 'Active' ? 'badge-active' : alert.status === 'Investigating' ? 'badge-investigating' : 'badge-resolved'}`}>
                                {alert.status}
                              </span>
                            </td>
                            <td style={{ textAlign: 'right' }}>
                              <div style={{ display: 'inline-flex', gap: '0.35rem' }}>
                                <button 
                                  className="btn btn-secondary btn-small" 
                                  style={{ padding: '0.2rem 0.4rem', width: 'auto' }}
                                  onClick={() => handleUpdateThreatStatus(alert.id, alert.status)}
                                  title="Cycle Status"
                                >
                                  {alert.status === 'Active' ? <Clock size={12} /> : <CheckCircle2 size={12} />}
                                </button>
                                <button 
                                  className="btn btn-danger btn-small" 
                                  style={{ padding: '0.2rem 0.4rem', width: 'auto' }}
                                  onClick={() => handleDeleteThreatAlert(alert.id)}
                                >
                                  <Trash2 size={12} />
                                </button>
                              </div>
                            </td>
                          </tr>
                        ))
                      )}
                    </tbody>
                  </table>
                </div>
              </div>

            </div>
          )}

          {/* TAB 6: REPORTS EXPORTER */}
          {activeTab === 'exporter' && (
            <div style={{ display: 'flex', flexDirection: 'column', gap: '1.5rem' }}>
              
              {/* Exporter Introduction */}
              <div className="card">
                <div className="metric-card-header">
                  <h2 style={{ fontSize: '1.2rem', display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                    <FileSpreadsheet size={22} style={{ color: 'var(--primary)' }} />
                    Compliance & System Reports Exporter
                  </h2>
                </div>
                <p style={{ marginTop: '0.5rem', color: 'var(--text-secondary)', fontSize: '0.9rem', lineHeight: 1.6 }}>
                  Download official compliance logs, phishing audit ledgers, security alert registers, and system operator directories. Export formats are fully standardized in **Comma-Separated Values (CSV)** and **Structured JSON** formats for direct import into third-party security orchestration (SOAR) or compliance auditing systems.
                </p>
              </div>

              {/* Exporter Cards Grid */}
              <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(240px, 1fr))', gap: '1.25rem' }}>
                {[
                  {
                    title: 'Operators Registry',
                    description: 'Full list of active and deactivated operator credentials, emails, roles, and signup timestamps.',
                    count: profiles.length,
                    data: profiles,
                    filename: 'cybershield_operators_directory'
                  },
                  {
                    title: 'Phishing Scans Audit',
                    description: 'Audit history of scanned URLs, Emails, SMS content, results verdict, and confidence scores.',
                    count: scans.length,
                    data: scans,
                    filename: 'cybershield_phishing_scans_audit'
                  },
                  {
                    title: 'Incident Threat Logs',
                    description: 'System threat entries, authentication logs, failed login tracking, and resolution details.',
                    count: threatLogs.length,
                    data: threatLogs,
                    filename: 'cybershield_threat_incidents_ledger'
                  },
                  {
                    title: 'Security Engine Alerts',
                    description: 'Real-time alert notifications generated from user behavior thresholds and risk indexes.',
                    count: alerts.length,
                    data: alerts,
                    filename: 'cybershield_system_alerts_feed'
                  },
                  {
                    title: 'Threat Alerts Register',
                    description: 'Legacy threat alert entries and source IP addresses monitored by administrative operators.',
                    count: threatAlerts.length,
                    data: threatAlerts,
                    filename: 'cybershield_legacy_threat_register'
                  }
                ].map((item, idx) => (
                  <div key={idx} className="card" style={{ display: 'flex', flexDirection: 'column', justifyContent: 'space-between', height: '100%' }}>
                    <div>
                      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '0.75rem' }}>
                        <h3 style={{ fontSize: '1rem', fontWeight: 'bold' }}>{item.title}</h3>
                        <span className="badge" style={{ backgroundColor: 'var(--bg-tertiary)', color: 'var(--text-secondary)' }}>
                          {item.count} items
                        </span>
                      </div>
                      <p style={{ fontSize: '0.8rem', color: 'var(--text-secondary)', lineHeight: 1.5, marginBottom: '1.25rem' }}>
                        {item.description}
                      </p>
                    </div>

                    <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '0.5rem', marginTop: 'auto' }}>
                      <button
                        className="btn btn-secondary btn-small"
                        style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', gap: '0.25rem', height: '36px' }}
                        onClick={() => downloadCSV(item.data, item.filename)}
                        title="Export as CSV"
                      >
                        <Download size={13} />
                        CSV
                      </button>
                      <button
                        className="btn btn-primary btn-small"
                        style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', gap: '0.25rem', height: '36px' }}
                        onClick={() => downloadJSON(item.data, item.filename)}
                        title="Export as JSON"
                      >
                        <FileText size={13} />
                        JSON
                      </button>
                    </div>
                  </div>
                ))}
              </div>

            </div>
          )}

        </div>
      )}
    </div>
  );
};

export default AdminPanel;

