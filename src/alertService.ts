/**
 * CyberShield AI — Alert Engine Service (Phase 6)
 *
 * Fires alerts when:
 *  1. Failed logins exceed 5 within 10 minutes
 *  2. Phishing scan risk score (confidence) exceeds 80
 *  3. Multiple suspicious activities from the same user
 */

import { supabase } from './supabaseClient';

// ─── Types ───────────────────────────────────────────────────────────────────

export type AlertSeverity = 'Low' | 'Medium' | 'High' | 'Critical';

export type AlertType =
  | 'EXCESSIVE_FAILED_LOGINS'
  | 'HIGH_RISK_PHISHING_SCAN'
  | 'REPEATED_SUSPICIOUS_ACTIVITY'
  | 'BRUTE_FORCE_ALERT'
  | 'PHISHING_CAMPAIGN_ALERT'
  | 'ACCOUNT_COMPROMISE_RISK';

export interface AlertEntry {
  id: string;
  alert_type: AlertType;
  severity: AlertSeverity;
  title: string;
  message: string;
  user_email: string | null;
  trigger_value: number | null;
  trigger_threshold: number | null;
  is_read: boolean;
  is_dismissed: boolean;
  metadata: Record<string, any>;
  created_at: string;
}

// ─── Core Alert Writer ────────────────────────────────────────────────────────

export const fireAlert = async (params: {
  alert_type: AlertType;
  severity: AlertSeverity;
  title: string;
  message: string;
  user_email?: string | null;
  user_id?: string | null;
  trigger_value?: number;
  trigger_threshold?: number;
  metadata?: Record<string, any>;
}): Promise<void> => {
  try {
    const { error } = await supabase.from('alerts').insert([{
      alert_type: params.alert_type,
      severity: params.severity,
      title: params.title,
      message: params.message,
      user_email: params.user_email ?? null,
      user_id: params.user_id ?? null,
      trigger_value: params.trigger_value ?? null,
      trigger_threshold: params.trigger_threshold ?? null,
      is_read: false,
      is_dismissed: false,
      metadata: params.metadata ?? {},
    }]);

    if (error) {
      console.error('[AlertEngine] Insert error:', error.message);
    } else {
      console.info(`[AlertEngine] 🚨 Alert fired: ${params.alert_type} (${params.severity})`);
    }
  } catch (err) {
    console.error('[AlertEngine] Unexpected error:', err);
  }
};


// ─── Deduplication Guard ──────────────────────────────────────────────────────
// Prevents firing the same alert type for the same email more than once per window

const recentAlertCache = new Map<string, number>(); // key → last fired timestamp

const shouldFireAlert = (key: string, windowMs = 5 * 60 * 1000): boolean => {
  const last = recentAlertCache.get(key);
  if (last && Date.now() - last < windowMs) return false;
  recentAlertCache.set(key, Date.now());
  return true;
};

// ─── Trigger 1: Failed Logins > 5 in 10 Minutes ─────────────────────────────

export const checkFailedLoginAlert = async (email: string): Promise<void> => {
  const windowMs = 10 * 60 * 1000; // 10 minutes
  const threshold = 5;
  const since = new Date(Date.now() - windowMs).toISOString();

  const { count } = await supabase
    .from('failed_logins')
    .select('*', { count: 'exact', head: true })
    .eq('email', email)
    .gte('attempted_at', since);

  const failCount = count ?? 0;
  const cacheKey = `failed_login_alert:${email}`;

  if (failCount >= threshold && shouldFireAlert(cacheKey, windowMs)) {
    const severity: AlertSeverity = failCount >= 10 ? 'Critical' : 'High';

    await fireAlert({
      alert_type: 'EXCESSIVE_FAILED_LOGINS',
      severity,
      title: `🚨 Excessive Failed Logins Detected`,
      message: `Account "${email}" has had ${failCount} failed login attempts in the last 10 minutes — exceeding the threshold of ${threshold}. Possible brute-force attack in progress.`,
      user_email: email,
      trigger_value: failCount,
      trigger_threshold: threshold,
      metadata: {
        email,
        failed_count: failCount,
        window_minutes: 10,
        threshold,
        recommended_action: 'Lock the account and investigate source IPs immediately.',
      },
    });
  }
};

// ─── Trigger 2: Phishing Risk Score > 80 ─────────────────────────────────────

export const checkPhishingRiskAlert = async (params: {
  targetUrl: string;
  confidenceScore: number;
  result: 'Clean' | 'Suspicious' | 'Malicious';
  scanType: 'URL' | 'Email' | 'SMS';
  userEmail?: string;
  userId?: string;
}): Promise<void> => {
  const threshold = 80;

  if (params.confidenceScore <= threshold || params.result === 'Clean') return;

  const severity: AlertSeverity =
    params.confidenceScore >= 95 ? 'Critical' :
    params.confidenceScore >= 90 ? 'High' : 'Medium';

  const cacheKey = `phishing_risk:${params.targetUrl.slice(0, 60)}`;
  if (!shouldFireAlert(cacheKey, 2 * 60 * 1000)) return;

  const typeLabel = { URL: 'URL', Email: 'email content', SMS: 'SMS message' }[params.scanType];

  await fireAlert({
    alert_type: 'HIGH_RISK_PHISHING_SCAN',
    severity,
    title: `⚠️ High-Risk Phishing ${params.scanType} Detected`,
    message: `A ${typeLabel} was flagged with a risk score of ${params.confidenceScore}% (threshold: ${threshold}%). Verdict: ${params.result}. Immediate review recommended.`,
    user_email: params.userEmail ?? null,
    user_id: params.userId ?? null,
    trigger_value: params.confidenceScore,
    trigger_threshold: threshold,
    metadata: {
      target: params.targetUrl.slice(0, 200),
      confidence_score: params.confidenceScore,
      result: params.result,
      scan_type: params.scanType,
      threshold,
      recommended_action: 'Block the sender/domain and notify affected users.',
    },
  });
};

// ─── Trigger 3: Repeated Suspicious Activity from Same User ──────────────────

export const checkRepeatedSuspiciousActivity = async (userEmail: string, userId?: string): Promise<void> => {
  const windowMs = 15 * 60 * 1000; // 15 minutes
  const threshold = 3;
  const since = new Date(Date.now() - windowMs).toISOString();

  // Count suspicious + malicious scans from this user in the window
  const { count: suspCount } = await supabase
    .from('phishing_scans')
    .select('*', { count: 'exact', head: true })
    .in('result', ['Suspicious', 'Malicious'])
    .gte('scanned_at', since);

  const count = suspCount ?? 0;
  const cacheKey = `repeated_suspicious:${userEmail}`;

  if (count >= threshold && shouldFireAlert(cacheKey, windowMs)) {
    const severity: AlertSeverity = count >= 6 ? 'Critical' : 'High';

    await fireAlert({
      alert_type: 'REPEATED_SUSPICIOUS_ACTIVITY',
      severity,
      title: `🔁 Repeated Suspicious Activity Detected`,
      message: `User "${userEmail}" has triggered ${count} suspicious/malicious scan results in the last 15 minutes (threshold: ${threshold}). This may indicate coordinated phishing reconnaissance.`,
      user_email: userEmail,
      user_id: userId ?? null,
      trigger_value: count,
      trigger_threshold: threshold,
      metadata: {
        user_email: userEmail,
        suspicious_count: count,
        window_minutes: 15,
        threshold,
        recommended_action: 'Review all recent scans from this user and consider rate limiting.',
      },
    });
  }
};

// ─── Fetch Helpers ────────────────────────────────────────────────────────────

export const fetchAlerts = async (limit = 50): Promise<AlertEntry[]> => {
  const { data, error } = await supabase
    .from('alerts')
    .select('*')
    .eq('is_dismissed', false)
    .order('created_at', { ascending: false })
    .limit(limit);

  if (error) { console.error('[AlertEngine] Fetch error:', error.message); return []; }
  return (data ?? []) as AlertEntry[];
};

export const getUnreadAlertCount = async (): Promise<number> => {
  const { count, error } = await supabase
    .from('alerts')
    .select('*', { count: 'exact', head: true })
    .eq('is_read', false)
    .eq('is_dismissed', false);

  if (error) return 0;
  return count ?? 0;
};

export const markAlertRead = async (id: string): Promise<void> => {
  await supabase.from('alerts').update({ is_read: true }).eq('id', id);
};

export const markAllAlertsRead = async (): Promise<void> => {
  await supabase.from('alerts').update({ is_read: true }).eq('is_read', false);
};

export const dismissAlert = async (id: string): Promise<void> => {
  await supabase.from('alerts').update({ is_dismissed: true }).eq('id', id);
};
