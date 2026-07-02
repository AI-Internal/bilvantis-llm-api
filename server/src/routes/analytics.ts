import { Router } from 'express';
import type { Request, Response } from 'express';
import { getDb } from '../db/index.js';
import { FALLBACK_INPUT_PER_M, FALLBACK_OUTPUT_PER_M } from '../db/model-pricing.js';
import type { SessionUser } from '../services/auth.js';

export const analyticsRouter = Router();

// Multi-tenant: every user sees ONLY their own usage. All analytics read the
// raw `requests` table filtered by the session user's id. That table is capped
// by REQUEST_ANALYTICS_MAX_ROWS / RETENTION_DAYS (defaults 100k rows / 90d), so
// per-user history spans that window — ample for a team's operational view. The
// install-wide `request_hourly` / lifetime-settings aggregates are intentionally
// NOT used here (they are not per-user).
const uid = (req: Request): number => (req as Request & { user?: SessionUser }).user!.userId;

// Format UTC timestamps the same way SQLite stores created_at text values.
const toSqliteDateTime = (timestamp: number) =>
    new Date(timestamp).toISOString().slice(0, 19).replace('T', ' ');

// Return the rolling cutoff timestamp for the selected analytics range.
function getSinceTimestamp(range: string): string {
  const now = Date.now();

  switch (range) {
    case '24h':
      return toSqliteDateTime(now - 24 * 60 * 60 * 1000);
    case '30d':
      return toSqliteDateTime(now - 30 * 24 * 60 * 60 * 1000);
    case '7d':
    default:
      return toSqliteDateTime(now - 7 * 24 * 60 * 60 * 1000);
  }
}

// Summary stats (per-user)
analyticsRouter.get('/summary', (req: Request, res: Response) => {
  const range = (req.query.range as string) ?? '7d';
  const since = getSinceTimestamp(range);
  const db = getDb();
  const userId = uid(req);

  const totals = db.prepare(`
    SELECT
      COUNT(*) as total_requests,
      SUM(CASE WHEN status = 'success' THEN 1 ELSE 0 END) as success_count,
      COALESCE(SUM(input_tokens), 0) as total_input_tokens,
      COALESCE(SUM(output_tokens), 0) as total_output_tokens,
      AVG(latency_ms) as avg_latency_ms,
      SUM(CASE WHEN requested_model IS NOT NULL THEN 1 ELSE 0 END) as pinned_count,
      SUM(CASE WHEN requested_model = model_id THEN 1 ELSE 0 END) as pin_honored_count
    FROM requests
    WHERE user_id = ? AND created_at >= ?
  `).get(userId, since) as {
    total_requests: number; success_count: number | null;
    total_input_tokens: number; total_output_tokens: number;
    avg_latency_ms: number | null; pinned_count: number | null; pin_honored_count: number | null;
  };

  const totalRequests = totals.total_requests ?? 0;
  const successRate = totalRequests > 0 ? ((totals.success_count ?? 0) / totalRequests) * 100 : 0;

  const savings = db.prepare(`
    SELECT COALESCE(SUM(
      CASE WHEN r.status = 'success' THEN
        r.input_tokens  * COALESCE(m.paid_input_per_m,  ?) / 1000000.0 +
        r.output_tokens * COALESCE(m.paid_output_per_m, ?) / 1000000.0
      ELSE 0 END
    ), 0) as est_savings
    FROM requests r
    LEFT JOIN models m ON m.platform = r.platform AND m.model_id = r.model_id
    WHERE r.user_id = ? AND r.created_at >= ?
  `).get(FALLBACK_INPUT_PER_M, FALLBACK_OUTPUT_PER_M, userId, since) as { est_savings: number };

  // Lifetime (per-user, within retention): oldest row + total count for this user.
  const lifetime = db.prepare(`
    SELECT MIN(created_at) as first_request_at, COUNT(*) as total
    FROM requests WHERE user_id = ?
  `).get(userId) as { first_request_at: string | null; total: number };

  res.json({
    totalRequests,
    successRate: Math.round(successRate * 10) / 10,
    totalInputTokens: totals.total_input_tokens ?? 0,
    totalOutputTokens: totals.total_output_tokens ?? 0,
    avgLatencyMs: Math.round(totals.avg_latency_ms ?? 0),
    estimatedCostSavings: Math.round((savings.est_savings ?? 0) * 100) / 100,
    pinnedRequests: totals.pinned_count ?? 0,
    pinHonoredRequests: totals.pin_honored_count ?? 0,
    firstRequestAt: lifetime.first_request_at ?? null,
    lifetimeTotalRequests: lifetime.total ?? 0,
  });
});

// Stats grouped by model (per-user)
analyticsRouter.get('/by-model', (req: Request, res: Response) => {
  const range = (req.query.range as string) ?? '7d';
  const since = getSinceTimestamp(range);
  const db = getDb();

  const rows = db.prepare(`
    SELECT
      r.platform,
      r.model_id,
      m.display_name,
      COUNT(*) as requests,
      SUM(CASE WHEN r.status = 'success' THEN 1 ELSE 0 END) * 100.0 / COUNT(*) as success_rate,
      AVG(r.latency_ms) as avg_latency_ms,
      SUM(r.input_tokens) as total_input_tokens,
      SUM(r.output_tokens) as total_output_tokens,
      SUM(CASE WHEN r.requested_model = r.model_id THEN 1 ELSE 0 END) as pinned_requests,
      SUM(CASE WHEN r.status = 'success' THEN
        r.input_tokens  * COALESCE(m.paid_input_per_m,  ?) / 1000000.0 +
        r.output_tokens * COALESCE(m.paid_output_per_m, ?) / 1000000.0
      ELSE 0 END) as est_cost
    FROM requests r
    LEFT JOIN models m ON m.platform = r.platform AND m.model_id = r.model_id
    WHERE r.user_id = ? AND r.created_at >= ?
    GROUP BY r.platform, r.model_id
    ORDER BY requests DESC
  `).all(FALLBACK_INPUT_PER_M, FALLBACK_OUTPUT_PER_M, uid(req), since) as any[];

  res.json(rows.map(r => ({
    platform: r.platform,
    modelId: r.model_id,
    displayName: r.display_name ?? r.model_id,
    requests: r.requests,
    successRate: Math.round(r.success_rate * 10) / 10,
    avgLatencyMs: Math.round(r.avg_latency_ms),
    totalInputTokens: r.total_input_tokens ?? 0,
    totalOutputTokens: r.total_output_tokens ?? 0,
    pinnedRequests: r.pinned_requests ?? 0,
    estimatedCost: Math.round((r.est_cost ?? 0) * 100) / 100,
  })));
});

// Stats grouped by platform (per-user)
analyticsRouter.get('/by-platform', (req: Request, res: Response) => {
  const range = (req.query.range as string) ?? '7d';
  const since = getSinceTimestamp(range);
  const db = getDb();

  const rows = db.prepare(`
    SELECT
      platform,
      COUNT(*) as requests,
      SUM(CASE WHEN status = 'success' THEN 1 ELSE 0 END) * 100.0 / COUNT(*) as success_rate,
      AVG(latency_ms) as avg_latency_ms,
      SUM(input_tokens) as total_input_tokens,
      SUM(output_tokens) as total_output_tokens
    FROM requests
    WHERE user_id = ? AND created_at >= ?
    GROUP BY platform
    ORDER BY requests DESC
  `).all(uid(req), since) as any[];

  res.json(rows.map(r => ({
    platform: r.platform,
    requests: r.requests,
    successRate: Math.round(r.success_rate * 10) / 10,
    avgLatencyMs: Math.round(r.avg_latency_ms),
    totalInputTokens: r.total_input_tokens ?? 0,
    totalOutputTokens: r.total_output_tokens ?? 0,
  })));
});

// Timeline data (per-user), bucketed from the raw rows.
analyticsRouter.get('/timeline', (req: Request, res: Response) => {
  const range = (req.query.range as string) ?? '7d';
  const interval = (req.query.interval as string) ?? (range === '24h' ? 'hour' : 'day');
  const since = getSinceTimestamp(range);
  const db = getDb();

  // dateFormat is a hardcoded whitelist — never user-controlled.
  const dateFormat = interval === 'hour' ? '%Y-%m-%dT%H:00:00' : '%Y-%m-%d';

  const rows = db.prepare(`
    SELECT
      strftime('${dateFormat}', created_at) as timestamp,
      COUNT(*) as requests,
      SUM(CASE WHEN status = 'success' THEN 1 ELSE 0 END) as success_count,
      SUM(CASE WHEN status = 'error' THEN 1 ELSE 0 END) as failure_count
    FROM requests
    WHERE user_id = ? AND created_at >= ?
    GROUP BY strftime('${dateFormat}', created_at)
    ORDER BY timestamp ASC
  `).all(uid(req), since) as any[];

  res.json(rows.map(r => ({
    timestamp: r.timestamp,
    requests: r.requests,
    successCount: r.success_count,
    failureCount: r.failure_count,
  })));
});

// Error distribution (per-user, grouped by error type and platform)
analyticsRouter.get('/error-distribution', (req: Request, res: Response) => {
  const range = (req.query.range as string) ?? '7d';
  const since = getSinceTimestamp(range);
  const db = getDb();
  const userId = uid(req);

  const rows = db.prepare(`
    SELECT
      platform,
      model_id,
      CASE
        WHEN error LIKE '%429%' OR error LIKE '%rate limit%' OR error LIKE '%too many%' OR error LIKE '%quota%' THEN 'Rate Limited (429)'
        WHEN error LIKE '%401%' OR error LIKE '%unauthorized%' OR error LIKE '%invalid.*key%' THEN 'Auth Error (401)'
        WHEN error LIKE '%403%' OR error LIKE '%forbidden%' THEN 'Forbidden (403)'
        WHEN error LIKE '%404%' OR error LIKE '%not found%' THEN 'Not Found (404)'
        WHEN error LIKE '%timeout%' OR error LIKE '%ETIMEDOUT%' OR error LIKE '%ECONNREFUSED%' THEN 'Timeout/Connection'
        WHEN error LIKE '%500%' OR error LIKE '%internal server%' THEN 'Server Error (500)'
        WHEN error LIKE '%503%' OR error LIKE '%unavailable%' THEN 'Unavailable (503)'
        ELSE 'Other'
      END as error_category,
      COUNT(*) as count
    FROM requests
    WHERE status = 'error' AND user_id = ? AND created_at >= ?
    GROUP BY platform, error_category
    ORDER BY count DESC
  `).all(userId, since) as any[];

  const byCategory = db.prepare(`
    SELECT
      CASE
        WHEN error LIKE '%429%' OR error LIKE '%rate limit%' OR error LIKE '%too many%' OR error LIKE '%quota%' THEN 'Rate Limited (429)'
        WHEN error LIKE '%401%' OR error LIKE '%unauthorized%' OR error LIKE '%invalid.*key%' THEN 'Auth Error (401)'
        WHEN error LIKE '%403%' OR error LIKE '%forbidden%' THEN 'Forbidden (403)'
        WHEN error LIKE '%404%' OR error LIKE '%not found%' THEN 'Not Found (404)'
        WHEN error LIKE '%timeout%' OR error LIKE '%ETIMEDOUT%' OR error LIKE '%ECONNREFUSED%' THEN 'Timeout/Connection'
        WHEN error LIKE '%500%' OR error LIKE '%internal server%' THEN 'Server Error (500)'
        WHEN error LIKE '%503%' OR error LIKE '%unavailable%' THEN 'Unavailable (503)'
        ELSE 'Other'
      END as category,
      COUNT(*) as count
    FROM requests
    WHERE status = 'error' AND user_id = ? AND created_at >= ?
    GROUP BY category
    ORDER BY count DESC
  `).all(userId, since) as any[];

  const byPlatform = db.prepare(`
    SELECT platform, COUNT(*) as count
    FROM requests
    WHERE status = 'error' AND user_id = ? AND created_at >= ?
    GROUP BY platform
    ORDER BY count DESC
  `).all(userId, since) as any[];

  res.json({
    byCategory,
    byPlatform,
    detailed: rows,
  });
});

// Recent errors (per-user)
analyticsRouter.get('/errors', (req: Request, res: Response) => {
  const range = (req.query.range as string) ?? '7d';
  const since = getSinceTimestamp(range);
  const db = getDb();

  const rows = db.prepare(`
    SELECT id, platform, model_id, error, latency_ms, created_at
    FROM requests
    WHERE status = 'error' AND user_id = ? AND created_at >= ?
    ORDER BY created_at DESC
    LIMIT 50
  `).all(uid(req), since) as any[];

  res.json(rows.map(r => ({
    id: r.id,
    platform: r.platform,
    modelId: r.model_id,
    error: r.error,
    latencyMs: r.latency_ms,
    createdAt: r.created_at,
  })));
});
