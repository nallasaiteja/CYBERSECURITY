import React, { useEffect, useState, useCallback } from 'react';
import {
  AlertTriangle,
  RefreshCw,
  Radio,
  Users,
  Globe,
  Ban,
  TrendingUp,
  BarChart3,
  Mail,
  MessageSquare,
  ShieldAlert,
  Activity,
  UserCheck
} from 'lucide-react';
import { supabase } from '../supabaseClient';
import { useAuth } from '../contexts/AuthContext';
import { onPhishingScan } from '../threatService';

// ─── Types ───────────────────────────────────────────────────────────────────

type ScanResult = 'Clean' | 'Suspicious' | 'Malicious';
type ScanMode = 'URL' | 'Email' | 'SMS';



interface PhishingScan {
  id: string;
  target_url: string;
  result: ScanResult;
  confidence_score: number;
  scan_type: ScanMode;
  content_snippet?: string;
  scanned_at: string;
  user_id?: string;
}

interface FailedLogin {
  id: string;
  email: string;
  ip_address: string;
  attempted_at: string;
}

interface ThreatLogEntry {
  id: string;
  event_type: string;
  severity: 'Low' | 'Medium' | 'High' | 'Critical';
  description: string;
  user_id: string | null;
  user_email: string | null;
  ip_address: string | null;
  metadata: Record<string, any>;
  resolved: boolean;
  created_at: string;
}



interface DetectionSignal {
  id: string;
  triggered: boolean;
  weight: number;
  shortLabel: string;
  reason: string;
  explanation: string;
  recommendation: string;
}

interface AIAnalysisReport {
  verdict: ScanResult;
  confidence: number;
  riskScore: number;
  summary: string;
  signals: DetectionSignal[];
  recommendations: string[];
  whatHappened: string;
}

// ─── Heuristic Detectors (Phishing Sandbox) ───────────────────────────────────

const runURLAnalysis = (rawURL: string): AIAnalysisReport => {
  const url = rawURL.toLowerCase().trim();
  
  // Normalize the URL for parsing
  let cleanURL = url;
  if (!/^https?:\/\//i.test(cleanURL)) {
    cleanURL = 'http://' + cleanURL;
  }

  let hostname = '';
  try {
    const parsed = new URL(cleanURL);
    hostname = parsed.hostname;
  } catch (e) {
    hostname = cleanURL.replace(/^https?:\/\//i, '').split('/')[0].split('?')[0].split(':')[0];
  }

  const signals: DetectionSignal[] = [
    {
      id: 'ip_url', weight: 45, shortLabel: 'IP-Based URL',
      triggered: /^(\d{1,3}\.){3}\d{1,3}(:\d+)?$/i.test(hostname) || /https?:\/\/(\d{1,3}\.){3}\d{1,3}/i.test(url),
      reason: '🔴 Direct IP address used instead of a domain name',
      explanation: 'Legitimate websites always use domain names. Raw IP links are a classic phishing method to hide the true server identity and bypass domain registration checkers.',
      recommendation: 'Never log into pages using a direct IP address.'
    },
    {
      id: 'shortener', weight: 35, shortLabel: 'URL Shortener',
      triggered: ['bit.ly','tinyurl.com','t.co','goo.gl','ow.ly','short.io','rb.gy','cutt.ly','is.gd','tiny.cc'].some(s => hostname === s || hostname.endsWith('.' + s)),
      reason: '🟡 URL shortener service detected',
      explanation: 'Short links disguise the final landing page. Attackers use them to bypass reputation checkers and mask malicious domains.',
      recommendation: 'Expand shortened URLs using checkshorturl.com before clicking.'
    },
    {
      id: 'suspicious_tld', weight: 30, shortLabel: 'Suspicious TLD',
      triggered: (() => {
        const suspiciousTLDs = ['.tk','.ml','.ga','.cf','.gq','.xyz','.info','.online','.top','.club','.site','.website','.cc','.ru','.su','.space','.tech','.bid','.click'];
        return suspiciousTLDs.some(t => hostname.endsWith(t));
      })(),
      reason: '🟡 Cheap or free top-level domain (TLD)',
      explanation: 'Domains ending in cheap or free TLDs like .xyz, .tk, .ml are cheap to register, making them favorites for burner phishing servers.',
      recommendation: 'Only trust domains matching corporate standards (.com, .org, .net).'
    },
    {
      id: 'brand_impersonation', weight: 60, shortLabel: 'Brand Impersonation',
      triggered: (() => {
        const brands = ['paypal','google','microsoft','amazon','apple','facebook','netflix','chase','wellsfargo','citibank','bankofamerica'];
        return brands.some(b => {
          const lookalikes = [
            b,
            b.replace(/o/g, '0'),
            b.replace(/l/g, '1'),
            b.replace(/i/g, '1'),
            b.replace(/e/g, '3'),
            b.replace(/a/g, '4'),
            b.replace(/s/g, '5'),
            b.replace(/t/g, '7')
          ];
          
          return lookalikes.some(alt => {
            if (!hostname.includes(alt)) return false;
            const isLegit = (hostname === `${b}.com` || hostname === `www.${b}.com` || hostname.endsWith(`.${b}.com`));
            return !isLegit;
          });
        });
      })(),
      reason: '🔴 Brand name impersonation detected in fake domain',
      explanation: 'The URL contains a popular brand name or a look-alike variation (e.g., "paypa1-update.com") but is not owned by the official brand.',
      recommendation: 'Always type official addresses manually into your browser.'
    },
    {
      id: 'excessive_special_chars', weight: 25, shortLabel: 'Excessive Symbols',
      triggered: (() => {
        const hyphenCount = (hostname.match(/-/g) || []).length;
        const dotCount = (hostname.match(/\./g) || []).length;
        const symbolCount = (url.match(/[@%_]/g) || []).length;
        return hyphenCount >= 3 || dotCount >= 4 || symbolCount >= 1;
      })(),
      reason: '🔴 Excessive subdomains, hyphens, or redirect symbols detected',
      explanation: 'Phishing URLs stack multiple subdomains (dots) or hyphens to masquerade as safe subpages or include "@" symbols to silently redirect users to attacker servers.',
      recommendation: 'Ensure the host doesn\'t contain excessive dashes or subdomains.'
    },
    {
      id: 'phishing_keywords', weight: 35, shortLabel: 'Suspicious Keywords',
      triggered: (() => {
        const keywords = ['login', 'secure', 'verify', 'update', 'signin', 'banking', 'account', 'wallet', 'support', 'billing', 'credential', 'free-gift', 'free-rewards'];
        const hasKeyword = keywords.some(k => hostname.includes(k));
        const isCommonClean = ['microsoft.com', 'google.com', 'apple.com', 'amazon.com', 'facebook.com', 'netflix.com'].some(c => hostname === c || hostname.endsWith('.' + c));
        return hasKeyword && !isCommonClean;
      })(),
      reason: '🟡 Phishing keywords in hostname',
      explanation: 'Phishing websites use security-related keywords like "verify", "secure", "signin" in the domain name to deceive users into trusting the site.',
      recommendation: 'Verify the domain matches the official brand name exactly.'
    }
  ];

  let riskScore = 0;
  signals.forEach(s => { if (s.triggered) riskScore += s.weight; });
  return buildReport('URL', rawURL, riskScore, signals);
};

const runEmailAnalysis = (text: string): AIAnalysisReport => {
  const signals: DetectionSignal[] = [
    {
      id: 'urgency', weight: 25, shortLabel: 'Urgency Pressure',
      triggered: [/urgent/i,/immediate/i,/act now/i,/within 24 hours/i,/expires today/i].some(p => p.test(text)),
      reason: '🔴 Artificial urgency pressure language',
      explanation: 'Phishing emails threaten instant closure or penalties to make you act rashly without validating the request.',
      recommendation: 'Do not hurry. Verify security claims directly with your team.'
    },
    {
      id: 'harvesting', weight: 40, shortLabel: 'Credential Request',
      triggered: [/enter your password/i,/confirm your password/i,/update billing details/i,/verify credit card/i].some(p => p.test(text)),
      reason: '🔴 Credential harvesting language',
      explanation: 'Asking to provide password, card CVV, or PIN directly via email. Legitimate organizations never request this.',
      recommendation: 'Never send passphrases, pin codes, or bank details via email.'
    }
  ];

  let riskScore = 0;
  signals.forEach(s => { if (s.triggered) riskScore += s.weight; });
  return buildReport('Email', '[Email Body]', riskScore, signals);
};

const runSMSAnalysis = (text: string): AIAnalysisReport => {
  const signals: DetectionSignal[] = [
    {
      id: 'sms_bank', weight: 40, shortLabel: 'Fake Bank Alert',
      triggered: [/your (bank|card|account) has been locked/i,/unusual transaction detected/i,/verify payment/i].some(p => p.test(text)),
      reason: '🔴 Smishing bank alert mimic',
      explanation: 'Unsolicited texts claiming account restrictions are designed to scare you into logging into a fake banking site.',
      recommendation: 'Call the number on your bank card. Never click links in SMS.'
    }
  ];

  let riskScore = 0;
  signals.forEach(s => { if (s.triggered) riskScore += s.weight; });
  return buildReport('SMS', '[SMS Content]', riskScore, signals);
};

const buildReport = (_mode: ScanMode, _input: string, riskScore: number, signals: DetectionSignal[]): AIAnalysisReport => {
  let verdict: ScanResult = 'Clean';
  let confidence = 85;

  if (riskScore >= 50) {
    verdict = 'Malicious';
    confidence = Math.min(99, 70 + Math.round(riskScore / 3));
  } else if (riskScore >= 20) {
    verdict = 'Suspicious';
    confidence = Math.min(85, 50 + riskScore);
  } else {
    confidence = Math.max(90, 100 - riskScore * 3);
  }

  const triggered = signals.filter(s => s.triggered);
  const summary = verdict === 'Malicious' 
    ? `HIGH-RISK phishing attempt identified with ${confidence}% confidence score.`
    : verdict === 'Suspicious'
    ? `SUSPICIOUS indicators located with ${confidence}% confidence score. Exercise caution.`
    : `No significant phishing threats detected. Content is clean.`;

  const whatHappened = triggered.length > 0
    ? `Analysis detected: ${triggered.map(s => s.shortLabel).join(', ')}.`
    : `All security tests passed successfully.`;

  const recommendations = verdict === 'Malicious'
    ? ['🚫 Do NOT click links or download attachments.', '🗑️ Deactivate or delete the alert item immediately.']
    : verdict === 'Suspicious'
    ? ['⚠️ Contact your security department to confirm validity.', '🔍 Check sender email details closely.']
    : ['✅ Regular safety check. Always verify source links before logging in.'];

  return { verdict, confidence, riskScore, summary, signals, recommendations, whatHappened };
};

// ─── Dashboard Orchestrator ──────────────────────────────────────────────────

export const Dashboard: React.FC = () => {
  const { user, role } = useAuth();
  const [loading, setLoading] = useState(true);

  // Stats
  const [totalUsers, setTotalUsers] = useState(0);
  const [scans, setScans] = useState<PhishingScan[]>([]);
  const [threatLogs, setThreatLogs] = useState<ThreatLogEntry[]>([]);
  const [failedLogins, setFailedLogins] = useState<FailedLogin[]>([]);

  const fetchDashboardData = useCallback(async () => {
    try {
      setLoading(true);
      
      if (role === 'Admin') {
        const [uCount, scanRes, logRes, failRes] = await Promise.all([
          supabase.from('profiles').select('*', { count: 'exact', head: true }),
          supabase.from('phishing_scans').select('*').order('scanned_at', { ascending: false }),
          supabase.from('threat_logs').select('*').order('created_at', { ascending: false }),
          supabase.from('failed_logins').select('*').order('attempted_at', { ascending: false })
        ]);

        setTotalUsers(uCount.count || 0);
        setScans(scanRes.data || []);
        setThreatLogs(logRes.data || []);
        setFailedLogins(failRes.data || []);
      } else {
        // Standard User: Only select scans belonging to this user
        const { data, error } = await supabase
          .from('phishing_scans')
          .select('*')
          .eq('user_id', user?.id)
          .order('scanned_at', { ascending: false });

        if (!error && data) {
          setScans(data || []);
        }
        setTotalUsers(0);
        setThreatLogs([]);
        setFailedLogins([]);
      }
    } catch (e) {
      console.error('Data retrieval error:', e);
    } finally {
      setLoading(false);
    }
  }, [role, user?.id]);

  useEffect(() => {
    fetchDashboardData();

    // Subscribe to realtime updates for live cockpit sync
    const channels = [
      supabase.channel('dashboard_scans').on('postgres_changes', { event: '*', schema: 'public', table: 'phishing_scans' }, fetchDashboardData).subscribe(),
    ];

    if (role === 'Admin') {
      channels.push(
        supabase.channel('dashboard_threats').on('postgres_changes', { event: '*', schema: 'public', table: 'threat_logs' }, fetchDashboardData).subscribe(),
        supabase.channel('dashboard_logins').on('postgres_changes', { event: '*', schema: 'public', table: 'failed_logins' }, fetchDashboardData).subscribe()
      );
    }

    return () => {
      channels.forEach(ch => supabase.removeChannel(ch));
    };
  }, [fetchDashboardData, role]);



  // Render correct dashboard component
  if (role === 'Admin') {
    return (
      <AdminSOCDashboard 
        totalUsers={totalUsers} 
        scans={scans} 
        threatLogs={threatLogs} 
        failedLogins={failedLogins} 
        loading={loading} 
        onRefresh={fetchDashboardData}
      />
    );
  }

  return (
    <UserSecurityDashboard 
      scans={scans} 
      loading={loading} 
      onRefresh={fetchDashboardData}
      user={user}
    />
  );
};

// ─── SUB-COMPONENT: USER SECURITY DASHBOARD ──────────────────────────────────

interface UserDashboardProps {
  scans: PhishingScan[];
  loading: boolean;
  onRefresh: () => void;
  user: any;
}

const UserSecurityDashboard: React.FC<UserDashboardProps> = ({
  scans,
  loading,
  onRefresh,
  user
}) => {
  const [scanMode, setScanMode] = useState<ScanMode>('URL');
  const [urlInput, setUrlInput] = useState('');
  const [emailInput, setEmailInput] = useState('');
  const [smsInput, setSmsInput] = useState('');
  const [scanStatus, setScanStatus] = useState<'idle' | 'scanning' | 'success' | 'error'>('idle');
  const [aiReport, setAIReport] = useState<AIAnalysisReport | null>(null);

  const myScans = scans;

  const handleScan = async (e: React.FormEvent) => {
    e.preventDefault();
    const input = scanMode === 'URL' ? urlInput : scanMode === 'Email' ? emailInput : smsInput;
    if (!input.trim()) return;

    setScanStatus('scanning');
    setAIReport(null);

    setTimeout(async () => {
      const report = scanMode === 'URL' ? runURLAnalysis(input)
        : scanMode === 'Email' ? runEmailAnalysis(input)
        : runSMSAnalysis(input);

      setAIReport(report);

      try {
        const { error } = await supabase.from('phishing_scans').insert([{
          target_url: scanMode === 'URL' ? input : `[${scanMode} Content — ${new Date().toLocaleTimeString()}]`,
          result: report.verdict,
          confidence_score: report.confidence,
          scan_type: scanMode,
          content_snippet: scanMode !== 'URL' ? input.slice(0, 150).replace(/\n/g,' ') : null,
          scanned_at: new Date().toISOString(),
          user_id: user?.id
        }]);

        if (error) console.error('Scan save error:', error);
        
        if (scanMode === 'URL') setUrlInput('');
        else if (scanMode === 'Email') setEmailInput('');
        else setSmsInput('');

        setScanStatus('success');

        // Log phishing scan result to threat monitoring
        await onPhishingScan({
          targetUrl: input,
          result: report.verdict,
          confidence: report.confidence,
          scanType: scanMode,
          userEmail: user?.email
        });
      } catch (err) {
        console.error(err);
        setScanStatus('error');
      }
    }, 1200);
  };

  return (
    <div className="dashboard-container">
      <header className="dashboard-header">
        <div className="dashboard-title-area">
          <h1 style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
            <UserCheck size={26} style={{ color: 'var(--primary)' }} />
            Personal Security Dashboard
          </h1>
          <p className="auth-subtitle">Operator Profile: **{user?.email}** (Role: Standard User)</p>
        </div>
        <div style={{ display: 'flex', gap: '0.5rem', alignItems: 'center' }}>
          <div className="system-status-indicator">
            <Radio size={13}/>
            <span>Client Shield Active</span>
          </div>
          <button className="btn btn-secondary btn-small" onClick={onRefresh} disabled={loading}>
            <RefreshCw size={13} className={loading ? 'spin' : ''} />
          </button>
        </div>
      </header>

      {/* Main panel - Sandbox and Scan History */}
      <div className="dashboard-grid" style={{ gridTemplateColumns: '1.4fr 1fr', gap: '1.5rem', marginBottom: '1.5rem', alignItems: 'start' }}>
        
        {/* AI Analyzer Sandbox */}
        <div className="card">
          <div className="metric-card-header">
            <div>
              <h3 style={{ display: 'flex', alignItems: 'center', gap: '0.4rem' }}>
                <ShieldAlert size={18} style={{ color: 'var(--primary)' }} />
                AI Phishing Analyzer Sandbox
              </h3>
              <p className="auth-subtitle">Verify URL, Email, or SMS message content for phishing vectors</p>
            </div>
          </div>

          <div style={{ display: 'flex', gap: '0.4rem', marginBottom: '1rem', borderBottom: '1px solid var(--border-color)', paddingBottom: '0.75rem' }}>
            {(['URL', 'Email', 'SMS'] as ScanMode[]).map(mode => (
              <button
                key={mode}
                className={`btn btn-small ${scanMode === mode ? 'btn-primary' : 'btn-secondary'}`}
                style={{ width: 'auto', display: 'inline-flex', alignItems: 'center', gap: '0.3rem' }}
                onClick={() => {
                  setScanMode(mode);
                  setScanStatus('idle');
                  setAIReport(null);
                }}
              >
                {mode === 'URL' ? <Globe size={13}/> : mode === 'Email' ? <Mail size={13}/> : <MessageSquare size={13}/>}
                {mode} Scan
              </button>
            ))}
          </div>

          <form onSubmit={handleScan}>
            {scanMode === 'URL' ? (
              <div className="phishing-scanner-form">
                <input
                  type="text"
                  className="form-input"
                  placeholder="e.g. http://paypal-verify-login.secure-signin-web.ga"
                  value={urlInput}
                  onChange={e => setUrlInput(e.target.value)}
                  disabled={scanStatus === 'scanning'}
                  required
                />
                <button className="btn btn-primary" type="submit" disabled={scanStatus === 'scanning'}>
                  {scanStatus === 'scanning' ? 'Analyzing...' : 'Deploy Scan'}
                </button>
              </div>
            ) : (
              <div style={{ display: 'flex', flexDirection: 'column', gap: '0.75rem' }}>
                <textarea
                  className="form-input"
                  rows={4}
                  placeholder={scanMode === 'Email' ? 'Paste email body copy here...' : 'Paste text message here...'}
                  value={scanMode === 'Email' ? emailInput : smsInput}
                  onChange={e => scanMode === 'Email' ? setEmailInput(e.target.value) : setSmsInput(e.target.value)}
                  disabled={scanStatus === 'scanning'}
                  required
                  style={{ padding: '0.65rem 0.85rem', resize: 'vertical', fontSize: '0.85rem' }}
                />
                <button className="btn btn-primary" type="submit" disabled={scanStatus === 'scanning'}>
                  {scanStatus === 'scanning' ? 'Running Analysis...' : `Analyze ${scanMode}`}
                </button>
              </div>
            )}
          </form>

          {/* AI scan outputs */}
          {scanStatus === 'scanning' && (
            <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem', marginTop: '1rem', padding: '0.75rem', background: 'var(--bg-primary)', borderRadius: '8px', border: '1px solid var(--border-color)' }}>
              <div className="spinner" style={{ width: '20px', height: '20px', borderWidth: '2px' }} />
              <div>
                <div style={{ fontWeight: 'bold', fontSize: '0.85rem' }}>Analyzing threat vectors...</div>
                <div style={{ fontSize: '0.75rem', color: 'var(--text-secondary)' }}>Comparing patterns against phishing data indicators</div>
              </div>
            </div>
          )}

          {aiReport && (
            <div style={{ 
              marginTop: '1.25rem', padding: '1rem', borderRadius: '8px', 
              border: `1px solid ${aiReport.verdict === 'Malicious' ? 'rgba(239,68,68,0.3)' : aiReport.verdict === 'Suspicious' ? 'rgba(249,115,22,0.3)' : 'rgba(16,185,129,0.3)'}`,
              background: 'var(--bg-primary)'
            }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '0.5rem' }}>
                <div style={{ fontWeight: 'bold', fontSize: '0.9rem', color: aiReport.verdict === 'Malicious' ? 'var(--danger)' : aiReport.verdict === 'Suspicious' ? 'var(--warning)' : 'var(--success)' }}>
                  Verdict: {aiReport.verdict} ({aiReport.confidence}% confidence)
                </div>
              </div>
              <p style={{ fontSize: '0.82rem', lineHeight: 1.5, margin: 0 }}>{aiReport.summary}</p>
              
              {aiReport.signals.filter(s => s.triggered).length > 0 && (
                <div style={{ marginTop: '0.75rem', borderTop: '1px solid var(--border-color)', paddingTop: '0.75rem' }}>
                  <div style={{ fontSize: '0.72rem', fontWeight: 700, textTransform: 'uppercase', color: 'var(--text-secondary)', marginBottom: '0.4rem', letterSpacing: '0.05em' }}>
                    🚨 Detected Threat Signals:
                  </div>
                  <ul style={{ margin: 0, paddingLeft: '1.2rem', display: 'flex', flexDirection: 'column', gap: '0.4rem' }}>
                    {aiReport.signals.filter(s => s.triggered).map(s => (
                      <li key={s.id} style={{ fontSize: '0.78rem', color: 'var(--text-primary)' }}>
                        <span style={{ fontWeight: 600, color: 'var(--warning)' }}>{s.shortLabel}</span>: {s.reason}
                        <div style={{ fontSize: '0.72rem', color: 'var(--text-secondary)', marginTop: '0.1rem', lineHeight: 1.4 }}>{s.explanation}</div>
                      </li>
                    ))}
                  </ul>
                </div>
              )}

              <div style={{ fontSize: '0.75rem', color: 'var(--text-secondary)', marginTop: '0.75rem', fontWeight: 600, borderTop: aiReport.signals.filter(s => s.triggered).length > 0 ? '1px solid var(--border-color)' : 'none', paddingTop: aiReport.signals.filter(s => s.triggered).length > 0 ? '0.5rem' : '0' }}>
                💡 Recommendation: {aiReport.recommendations[0]}
              </div>
            </div>
          )}
        </div>

        {/* Personal scans feed */}
        <div className="card" style={{ padding: '1.25rem' }}>
          <div className="section-header">
            <div>
              <h2 style={{ fontSize: '1.1rem', display: 'flex', alignItems: 'center', gap: '0.4rem', margin: 0 }}>
                <Globe size={18} style={{ color: 'var(--primary)' }} />
                My Scan History
              </h2>
              <p className="auth-subtitle">Phishing sandbox runs by this profile</p>
            </div>
          </div>
          {loading ? (
            <div style={{ display: 'flex', flexDirection: 'column', gap: '0.5rem', padding: '1rem' }}>
              <div className="skeleton skeleton-text" style={{ width: '100%' }}></div>
              <div className="skeleton skeleton-text" style={{ width: '90%' }}></div>
            </div>
          ) : myScans.length === 0 ? (
            <div style={{ textAlign: 'center', padding: '2.5rem 1rem', color: 'var(--text-muted)' }}>
              <Globe size={36} style={{ marginBottom: '0.5rem', opacity: 0.5, display: 'inline-block' }} />
              <p style={{ fontSize: '0.82rem' }}>No scan history. Run a check in the Sandbox to inspect links.</p>
            </div>
          ) : (
            <div className="table-responsive">
              <table className="cyber-table">
                <thead>
                  <tr>
                    <th>Scan Target</th>
                    <th>Type</th>
                    <th>Verdict</th>
                  </tr>
                </thead>
                <tbody>
                  {myScans.slice(0, 10).map(s => (
                    <tr key={s.id}>
                      <td style={{ maxWidth: '140px', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', fontSize: '0.8rem', fontWeight: 500 }} title={s.target_url}>
                        {s.target_url}
                      </td>
                      <td style={{ fontSize: '0.78rem' }}>{s.scan_type}</td>
                      <td>
                        {s.result === 'Malicious' && <span className="badge badge-critical">Malicious</span>}
                        {s.result === 'Suspicious' && <span className="badge badge-high">Suspicious</span>}
                        {s.result === 'Clean' && <span className="badge badge-active">Clean</span>}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>

      </div>
    </div>
  );
};

// ─── SUB-COMPONENT: ADMIN OPERATIONS CENTER (SOC) ────────────────────────────

interface AdminDashboardProps {
  totalUsers: number;
  scans: PhishingScan[];
  threatLogs: ThreatLogEntry[];
  failedLogins: FailedLogin[];
  loading: boolean;
  onRefresh: () => void;
}

const AdminSOCDashboard: React.FC<AdminDashboardProps> = ({
  totalUsers,
  scans,
  threatLogs,
  failedLogins,
  loading,
  onRefresh
}) => {
  // Compute analytics
  const activeThreats = threatLogs.filter(t => !t.resolved);
  const criticalThreats = activeThreats.filter(t => t.severity === 'Critical').length;
  const highThreats = activeThreats.filter(t => t.severity === 'High').length;
  
  const totalScans = scans.length;
  const maliciousScans = scans.filter(s => s.result === 'Malicious').length;
  const suspiciousScans = scans.filter(s => s.result === 'Suspicious').length;
  const cleanScans = scans.filter(s => s.result === 'Clean').length;

  // Compute Top Attacked Accounts (Emails with most logs or failed attempts)
  const getTopAttacked = () => {
    const counts: Record<string, number> = {};
    threatLogs.forEach(l => {
      if (l.user_email) counts[l.user_email] = (counts[l.user_email] || 0) + 1;
    });
    failedLogins.forEach(f => {
      if (f.email) counts[f.email] = (counts[f.email] || 0) + 1;
    });
    return Object.entries(counts)
      .map(([email, count]) => ({ email, count }))
      .sort((a, b) => b.count - a.count)
      .slice(0, 5);
  };

  const topAttacked = getTopAttacked();

  // Chart statistics percentages
  const scanDivisor = totalScans || 1;
  const cH = Math.max(10, (cleanScans / scanDivisor) * 120);
  const sH = Math.max(10, (suspiciousScans / scanDivisor) * 120);
  const mH = Math.max(10, (maliciousScans / scanDivisor) * 120);

  return (
    <div className="dashboard-container">
      <header className="dashboard-header">
        <div className="dashboard-title-area">
          <h1 style={{ display: 'flex', alignItems: 'center', gap: '0.6rem' }}>
            <Activity size={26} style={{ color: 'var(--danger)' }} />
            Security Operations Center (SOC)
          </h1>
          <p className="auth-subtitle">System-Wide Security Monitoring & Global Analytics</p>
        </div>
        <div style={{ display: 'flex', gap: '0.5rem', alignItems: 'center' }}>
          <div className="system-status-indicator" style={{ background: 'rgba(239,68,68,0.1)', color: 'var(--danger)', border: '1px solid rgba(239,68,68,0.3)' }}>
            <Radio size={13}/>
            <span>System Audits Live</span>
          </div>
          <button className="btn btn-secondary btn-small" onClick={onRefresh} disabled={loading}>
            <RefreshCw size={13} className={loading ? 'spin' : ''} />
          </button>
        </div>
      </header>

      {/* Metrics Cards Grid */}
      <div className="dashboard-grid" style={{ marginBottom: '1.5rem' }}>
        
        {/* Total Users */}
        <div className="card">
          <div className="metric-card-header"><h3>Total Users</h3><Users className="metric-icon" /></div>
          <div className="metric-value">{loading ? <div className="skeleton" style={{ height: '2.4rem', width: '60px' }}></div> : totalUsers}</div>
          <span className="metric-trend trend-up">Active registered operators</span>
        </div>

        {/* Total Phishing Scans */}
        <div className="card">
          <div className="metric-card-header"><h3>Total Phishing Scans</h3><Globe className="metric-icon" /></div>
          <div className="metric-value">{loading ? <div className="skeleton" style={{ height: '2.4rem', width: '60px' }}></div> : totalScans}</div>
          <span className="metric-trend trend-up">URL, Email, & SMS queries run</span>
        </div>

        {/* Active Threats */}
        <div className="card">
          <div className="metric-card-header">
            <h3>Active Threats</h3>
            <AlertTriangle className="metric-icon" style={{ color: activeThreats.length > 0 ? '#f97316' : undefined }} />
          </div>
          <div className="metric-value">{loading ? <div className="skeleton" style={{ height: '2.4rem', width: '60px' }}></div> : activeThreats.length}</div>
          <span className={`metric-trend ${activeThreats.length > 0 ? 'trend-down' : 'trend-up'}`}>
            {criticalThreats} Critical / {highThreats} High priority
          </span>
        </div>

        {/* Failed Logins */}
        <div className="card">
          <div className="metric-card-header">
            <h3>Failed Logins</h3>
            <Ban className="metric-icon" style={{ color: failedLogins.length > 0 ? 'var(--danger)' : undefined }} />
          </div>
          <div className="metric-value">{loading ? <div className="skeleton" style={{ height: '2.4rem', width: '60px' }}></div> : failedLogins.length}</div>
          <span className="metric-trend trend-down">Global login failures audited</span>
        </div>

      </div>

      {/* Analytics Charts Grid */}
      <div className="charts-grid" style={{ marginBottom: '1.5rem' }}>
        
        {/* Threat Trends Line Chart */}
        <div className="card chart-card">
          <div className="metric-card-header">
            <h3 style={{ display: 'flex', alignItems: 'center', gap: '0.4rem' }}>
              <TrendingUp size={18} style={{ color: 'var(--primary)' }} />
              Global Threat Trends
            </h3>
            <span style={{ fontSize: '0.72rem', color: 'var(--text-muted)' }}>Last 5 Days Activity</span>
          </div>
          <div className="chart-container">
            <svg className="svg-chart" viewBox="0 0 400 150">
              <line x1="10" y1="30" x2="390" y2="30" stroke="var(--border-color)" strokeWidth="1" strokeDasharray="4 4"/>
              <line x1="10" y1="80" x2="390" y2="80" stroke="var(--border-color)" strokeWidth="1" strokeDasharray="4 4"/>
              <line x1="10" y1="130" x2="390" y2="130" stroke="var(--border-color)" strokeWidth="1"/>
              <path d="M 20 120 C 80 100, 100 60, 150 75 C 200 90, 240 30, 280 40 C 330 50, 350 110, 380 90 L 380 130 L 20 130 Z" fill="rgba(6,182,212,0.1)"/>
              <path d="M 20 120 C 80 100, 100 60, 150 75 C 200 90, 240 30, 280 40 C 330 50, 350 110, 380 90" fill="none" stroke="var(--primary)" strokeWidth="2.5"/>
              {[[20,120],[150,75],[280,40],[380,90]].map(([x,y],i) => <circle key={i} cx={x} cy={y} r="4.5" fill="var(--primary)" stroke="var(--bg-secondary)" strokeWidth="1.5"/>)}
              {['Day -4','Day -3','Day -2','Day -1','Today'].map((l,i) => <text key={i} x={20+i*90} y="145" fill="var(--text-muted)" fontSize="9" textAnchor="middle">{l}</text>)}
            </svg>
          </div>
        </div>

        {/* Scan Verdicts Bar Chart */}
        <div className="card chart-card">
          <div className="metric-card-header">
            <h3 style={{ display: 'flex', alignItems: 'center', gap: '0.4rem' }}>
              <BarChart3 size={18} style={{ color: 'var(--primary)' }} />
              Security Analytics (Scan verdicts)
            </h3>
            <span style={{ fontSize: '0.72rem', color: 'var(--text-muted)' }}>Scan Verdict Ratios</span>
          </div>
          <div className="chart-container">
            <svg className="svg-chart" viewBox="0 0 300 150">
              <line x1="10" y1="130" x2="290" y2="130" stroke="var(--border-color)" strokeWidth="1"/>
              
              {/* Clean */}
              <rect x="45" y={130-cH} width="40" height={cH} fill="var(--success)" rx="4"/>
              <text x="65" y={Math.max(15,120-cH)} fill="var(--text-primary)" fontSize="10" fontWeight="bold" textAnchor="middle">{cleanScans}</text>
              
              {/* Suspicious */}
              <rect x="130" y={130-sH} width="40" height={sH} fill="var(--warning)" rx="4"/>
              <text x="150" y={Math.max(15,120-sH)} fill="var(--text-primary)" fontSize="10" fontWeight="bold" textAnchor="middle">{suspiciousScans}</text>
              
              {/* Malicious */}
              <rect x="215" y={130-mH} width="40" height={mH} fill="var(--danger)" rx="4"/>
              <text x="235" y={Math.max(15,120-mH)} fill="var(--text-primary)" fontSize="10" fontWeight="bold" textAnchor="middle">{maliciousScans}</text>

              {[['Clean','65'],['Suspicious','150'],['Malicious','235']].map(([l,x],i) => <text key={i} x={+x} y="145" fill="var(--text-secondary)" fontSize="10" textAnchor="middle">{l}</text>)}
            </svg>
          </div>
        </div>

      </div>

      {/* Global Feeds Table & Lists */}
      <div className="dashboard-subgrid" style={{ gridTemplateColumns: '1.25fr 1fr' }}>
        
        {/* Global threat logs (All users) */}
        <div className="alerts-section" style={{ marginTop: 0 }}>
          <div className="section-header">
            <div>
              <h2>Global threat Monitoring</h2>
              <p className="auth-subtitle">System-wide incident log feed</p>
            </div>
          </div>
          {loading ? (
            <div style={{ display: 'flex', flexDirection: 'column', gap: '0.5rem', padding: '1rem' }}>
              <div className="skeleton skeleton-text" style={{ width: '100%' }}></div>
              <div className="skeleton skeleton-text" style={{ width: '90%' }}></div>
            </div>
          ) : threatLogs.length === 0 ? (
            <p style={{ color: 'var(--text-secondary)', padding: '1rem' }}>No threat events logged.</p>
          ) : (
            <div className="table-responsive">
              <table className="cyber-table">
                <thead>
                  <tr>
                    <th>Type</th>
                    <th>Risk</th>
                    <th>Target Account</th>
                    <th>Time</th>
                  </tr>
                </thead>
                <tbody>
                  {threatLogs.slice(0, 6).map(log => (
                    <tr key={log.id}>
                      <td style={{ fontWeight: 500, fontSize: '0.8rem' }}>{log.event_type}</td>
                      <td>
                        <span className={`badge ${
                          log.severity === 'Critical' ? 'badge-critical' : 
                          log.severity === 'High' ? 'badge-high' : 
                          log.severity === 'Medium' ? 'badge-medium' : 'badge-low'
                        }`}>
                          {log.severity}
                        </span>
                      </td>
                      <td style={{ fontSize: '0.78rem', color: 'var(--text-secondary)' }}>{log.user_email ?? 'System'}</td>
                      <td style={{ fontSize: '0.75rem', color: 'var(--text-secondary)' }}>{new Date(log.created_at).toLocaleTimeString()}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>

        {/* Top Attacked Accounts */}
        <div className="alerts-section" style={{ marginTop: 0 }}>
          <div className="section-header">
            <div>
              <h2>Top Attacked Accounts</h2>
              <p className="auth-subtitle">Operators with highest threat indices</p>
            </div>
          </div>
          {loading ? (
            <div style={{ display: 'flex', flexDirection: 'column', gap: '0.5rem', padding: '1rem' }}>
              <div className="skeleton skeleton-text" style={{ width: '100%' }}></div>
              <div className="skeleton skeleton-text" style={{ width: '90%' }}></div>
            </div>
          ) : topAttacked.length === 0 ? (
            <p style={{ color: 'var(--text-secondary)', padding: '1rem' }}>All accounts safe.</p>
          ) : (
            <div className="table-responsive">
              <table className="cyber-table">
                <thead>
                  <tr>
                    <th>Account Email</th>
                    <th style={{ textAlign: 'right' }}>Threat Frequency</th>
                  </tr>
                </thead>
                <tbody>
                  {topAttacked.map((acc, i) => (
                    <tr key={i}>
                      <td style={{ fontWeight: 600, fontSize: '0.8rem' }}>{acc.email}</td>
                      <td style={{ textAlign: 'right', fontWeight: 'bold', color: 'var(--danger)', fontSize: '0.8rem' }}>
                        {acc.count} incidents
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>

      </div>
    </div>
  );
};

export default Dashboard;
