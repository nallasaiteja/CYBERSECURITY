/**
 * CyberShield AI — Threat Detection Service
 * 
 * Monitors events across the platform and automatically generates
 * threat log entries with appropriate severity levels.
 * 
 * Monitored Events:
 *  1. Failed login attempts
 *  2. Multiple logins from different locations (IP diversity)
 *  3. Excessive phishing scans (rate-based)
 *  4. Repeated suspicious/malicious scan results
 *  5. Admin actions (audit trail)
 */

import { supabase } from './supabaseClient';

// ─── Types ───────────────────────────────────────────────────────────────────

export type ThreatSeverity = 'Low' | 'Medium' | 'High' | 'Critical';

export type ThreatEventType =
  | 'FAILED_LOGIN'
  | 'BRUTE_FORCE_DETECTED'
  | 'MULTI_LOCATION_LOGIN'
  | 'EXCESSIVE_SCANS'
  | 'MALICIOUS_SCAN_DETECTED'
  | 'REPEATED_SUSPICIOUS_ACTIVITY'
  | 'ADMIN_ACTION'
  | 'ACCOUNT_LOCKOUT'
  | 'PHISHING_CAMPAIGN_DETECTED'
  | 'UNAUTHORIZED_ACCESS_ATTEMPT'
  | 'NEW_DEVICE_LOGIN'
  | 'NEW_LOCATION_LOGIN'
  | 'PASSWORD_RESET_ATTEMPT'
  | 'MULTIPLE_LOGIN_ATTEMPTS'
  | 'HIGH_RISK_PHISHING_SCAN'
  | 'SUSPICIOUS_USER_ACTIVITY';

export interface ThreatLogEntry {
  id: string;
  event_type: ThreatEventType;
  severity: ThreatSeverity;
  description: string;
  user_id: string | null;
  user_email: string | null;
  ip_address: string | null;
  metadata: Record<string, any>;
  resolved: boolean;
  created_at: string;
}

// ─── Email Dispatch Simulator ──────────────────────────────────────────────────

export const simulateEmailDispatch = (
  email: string,
  eventType: string,
  severity: string,
  description: string
) => {
  const subject = `[CyberShield AI] ⚠️ Security Threat Alert: ${eventType}`;
  const timestamp = new Date().toLocaleString();
  const emailContent = {
    id: Math.random().toString(36).substring(2, 9),
    to: email,
    subject,
    severity,
    description,
    body: `CyberShield AI Alert System\n---------------------------------\nIncident Signature: ${eventType}\nSeverity: ${severity}\nTrigger Time: ${timestamp}\nDetails: ${description}\n\nThis is an automated cybersecurity alert. Please review your account operations immediately.`,
    timestamp
  };

  // 1. Log to developer console with formatting
  console.info(
    `%c📧 [SMTP SERVER] Email dispatched successfully to: ${email}\n%cSubject: ${subject}\nSeverity: ${severity}\nContent: ${description}`,
    'color: #38bdf8; font-weight: bold; font-size: 11px;',
    'color: inherit;'
  );

  // 2. Save in localStorage for auditing
  try {
    const existing = JSON.parse(localStorage.getItem('cybershield-sent-emails') ?? '[]');
    existing.unshift(emailContent);
    localStorage.setItem('cybershield-sent-emails', JSON.stringify(existing.slice(0, 50)));
  } catch (e) {
    console.error('Failed to cache email dispatch:', e);
  }

  // 3. Dispatch global browser event for live UI toaster sync
  const event = new CustomEvent('security-email-sent', { detail: emailContent });
  window.dispatchEvent(event);
};

// ─── Core Logger ─────────────────────────────────────────────────────────────

export const logThreat = async (params: {
  event_type: ThreatEventType;
  severity: ThreatSeverity;
  description: string;
  user_email?: string | null;
  ip_address?: string | null;
  metadata?: Record<string, any>;
}) => {
  try {
    // Get current user if available (may be null for pre-auth events like failed logins)
    const { data: { user } } = await supabase.auth.getUser().catch(() => ({ data: { user: null } }));

    const { error } = await supabase.from('threat_logs').insert([{
      event_type: params.event_type,
      severity: params.severity,
      description: params.description,
      user_id: user?.id ?? null,           // null for unauthenticated events — that's fine
      user_email: params.user_email ?? user?.email ?? null,
      ip_address: params.ip_address ?? null,
      metadata: params.metadata ?? {},
      resolved: false,
    }]);

    if (error) {
      console.error('[ThreatService] Log insert error:', error.message, error.details);
    } else {
      const targetEmail = params.user_email ?? user?.email ?? null;
      if (targetEmail) {
        simulateEmailDispatch(targetEmail, params.event_type, params.severity, params.description);
      }
    }
  } catch (err) {
    console.error('[ThreatService] Unexpected error:', err);
  }
};

// ─── Event Monitors ──────────────────────────────────────────────────────────

/**
 * Call this every time a login attempt fails.
 */
export const onFailedLogin = async (email: string, ipAddress?: string) => {
  await logThreat({
    event_type: 'FAILED_LOGIN',
    severity: 'Low',
    description: `Failed login attempt for account: ${email}`,
    user_email: email,
    ip_address: ipAddress ?? null,
    metadata: { email, timestamp: new Date().toISOString() },
  });

  // Check if this account has had many recent failed attempts → brute force
  const since = new Date(Date.now() - 15 * 60 * 1000).toISOString(); // last 15 min
  const { count } = await supabase
    .from('failed_logins')
    .select('*', { count: 'exact', head: true })
    .eq('email', email)
    .gte('attempted_at', since);

  if ((count ?? 0) >= 5) {
    await logThreat({
      event_type: 'BRUTE_FORCE_DETECTED',
      severity: 'Critical',
      description: `Brute-force attack detected: ${count} failed logins in 15 minutes for ${email}`,
      user_email: email,
      ip_address: ipAddress ?? null,
      metadata: { email, failed_count: count, window_minutes: 15 },
    });
  } else if ((count ?? 0) >= 3) {
    await logThreat({
      event_type: 'ACCOUNT_LOCKOUT',
      severity: 'High',
      description: `Multiple failed logins detected: ${count} attempts for ${email} in the last 15 minutes`,
      user_email: email,
      ip_address: ipAddress ?? null,
      metadata: { email, failed_count: count },
    });
  }
};

/**
 * Call this whenever a phishing scan is submitted.
 * Detects excessive scanning and malicious findings.
 */
export const onPhishingScan = async (params: {
  targetUrl: string;
  result: 'Clean' | 'Suspicious' | 'Malicious';
  confidence: number;
  scanType: 'URL' | 'Email' | 'SMS';
  userEmail?: string;
}) => {
  // Log any malicious finding immediately
  if (params.result === 'Malicious') {
    await logThreat({
      event_type: 'MALICIOUS_SCAN_DETECTED',
      severity: params.confidence >= 90 ? 'Critical' : 'High',
      description: `Malicious ${params.scanType} detected (${params.confidence}% confidence): ${params.targetUrl.slice(0, 80)}`,
      user_email: params.userEmail ?? null,
      metadata: { result: params.result, confidence: params.confidence, scan_type: params.scanType, target: params.targetUrl },
    });
  }

  // Detect phishing campaign: 3+ malicious scans in 10 minutes
  const since = new Date(Date.now() - 10 * 60 * 1000).toISOString();
  const { count: malCount } = await supabase
    .from('phishing_scans')
    .select('*', { count: 'exact', head: true })
    .eq('result', 'Malicious')
    .gte('scanned_at', since);

  if ((malCount ?? 0) >= 3) {
    await logThreat({
      event_type: 'PHISHING_CAMPAIGN_DETECTED',
      severity: 'Critical',
      description: `Phishing campaign detected: ${malCount} malicious ${params.scanType}s submitted in the last 10 minutes`,
      user_email: params.userEmail ?? null,
      metadata: { malicious_count: malCount, window_minutes: 10 },
    });
  }

  // Detect excessive scanning: more than 15 total scans in 5 minutes
  const since5 = new Date(Date.now() - 5 * 60 * 1000).toISOString();
  const { count: scanCount } = await supabase
    .from('phishing_scans')
    .select('*', { count: 'exact', head: true })
    .gte('scanned_at', since5);

  if ((scanCount ?? 0) >= 15) {
    await logThreat({
      event_type: 'EXCESSIVE_SCANS',
      severity: 'Medium',
      description: `Excessive scan rate detected: ${scanCount} scans submitted in the last 5 minutes`,
      user_email: params.userEmail ?? null,
      metadata: { scan_count: scanCount, window_minutes: 5 },
    });
  }
};

/**
 * Call this on any admin action (for audit trail).
 */
export const onAdminAction = async (params: {
  action: string;
  targetId?: string;
  targetType?: string;
  adminEmail?: string;
  details?: Record<string, any>;
}) => {
  await logThreat({
    event_type: 'ADMIN_ACTION',
    severity: 'Low',
    description: `Admin action: ${params.action}${params.targetType ? ` on ${params.targetType}` : ''}`,
    user_email: params.adminEmail ?? null,
    metadata: {
      action: params.action,
      target_id: params.targetId,
      target_type: params.targetType,
      details: params.details ?? {},
      timestamp: new Date().toISOString(),
    },
  });
};

/**
 * Detects logins from multiple different IPs for the same account.
 * Call this after a successful login.
 */
export const onSuccessfulLogin = async (email: string, ipAddress?: string) => {
  // Check if this user has logged in from multiple IPs recently (24h window)
  const since = new Date(Date.now() - 24 * 60 * 60 * 1000).toISOString();
  const { data: recentLogins } = await supabase
    .from('failed_logins')
    .select('ip_address')
    .eq('email', email)
    .gte('attempted_at', since);

  const uniqueIPs = new Set((recentLogins ?? []).map(l => l.ip_address).filter(Boolean));
  if (ipAddress) uniqueIPs.add(ipAddress);

  if (uniqueIPs.size >= 3) {
    await logThreat({
      event_type: 'MULTI_LOCATION_LOGIN',
      severity: 'High',
      description: `Account ${email} accessed from ${uniqueIPs.size} different IP addresses in 24 hours`,
      user_email: email,
      ip_address: ipAddress ?? null,
      metadata: { email, unique_ips: Array.from(uniqueIPs), window_hours: 24 },
    });
  }
};

/**
 * Call this when a login occurs on a new device.
 */
export const onNewDeviceLogin = async (email: string, deviceName: string, ipAddress?: string) => {
  await logThreat({
    event_type: 'NEW_DEVICE_LOGIN',
    severity: 'Medium',
    description: `Login detected from a new device: ${deviceName} for account: ${email}`,
    user_email: email,
    ip_address: ipAddress ?? null,
    metadata: { email, device_name: deviceName, timestamp: new Date().toISOString() },
  });
};

/**
 * Call this when a login occurs from a new location/IP.
 */
export const onNewLocationLogin = async (email: string, location: string, ipAddress?: string) => {
  await logThreat({
    event_type: 'NEW_LOCATION_LOGIN',
    severity: 'Medium',
    description: `Login detected from a new location: ${location} for account: ${email}`,
    user_email: email,
    ip_address: ipAddress ?? null,
    metadata: { email, location, timestamp: new Date().toISOString() },
  });
};

/**
 * Call this when a password reset is requested.
 */
export const onPasswordResetAttempt = async (email: string, ipAddress?: string) => {
  await logThreat({
    event_type: 'PASSWORD_RESET_ATTEMPT',
    severity: 'Low',
    description: `Password reset request initiated for account: ${email}`,
    user_email: email,
    ip_address: ipAddress ?? null,
    metadata: { email, timestamp: new Date().toISOString() },
  });
};

/**
 * Call this when a user performs a suspicious activity.
 */
export const onSuspiciousActivity = async (email: string, activityDescription: string, ipAddress?: string) => {
  await logThreat({
    event_type: 'SUSPICIOUS_USER_ACTIVITY',
    severity: 'High',
    description: `Suspicious activity: ${activityDescription} for account: ${email}`,
    user_email: email,
    ip_address: ipAddress ?? null,
    metadata: { email, activity: activityDescription, timestamp: new Date().toISOString() },
  });
};

