import crypto from 'crypto';
import { getDb } from '../db/index.js';
import { hashPassword, verifyPassword } from '../lib/password.js';

// Dashboard authentication: email + password accounts with opaque session
// tokens. Distinct from a user's proxy key, which authenticates the /v1 proxy
// for their apps — this gates the /api/* admin surface for the human operator.
//
// Multi-tenant: every user owns their provider keys, their own proxy key, and
// their own usage. Role is 'admin' (curates the shared catalog/routing and
// manages users) or 'member'. The first account created is the admin.

const SESSION_TTL_MS = 30 * 24 * 60 * 60 * 1000; // 30 days

export type Role = 'admin' | 'member';

export interface SessionUser {
  userId: number;
  email: string;
  role: Role;
}

export interface UserRecord {
  id: number;
  email: string;
  role: Role;
  createdAt: string;
  hasKeys: number;
}

function sha256(s: string): string {
  return crypto.createHash('sha256').update(s).digest('hex');
}

function normalizeEmail(email: string): string {
  return email.trim().toLowerCase();
}

// Account creation is restricted to company domains. Override with a
// comma-separated ALLOWED_EMAIL_DOMAINS env var (e.g. to add a domain or, with
// '*', to allow any). Enforced by the account-creation routes (setup, register,
// admin-add) — the single place new users enter the system.
const DEFAULT_ALLOWED_DOMAINS = ['neoai.com', 'bilvantis.io', 'bilvantis.ai'];

export function allowedEmailDomains(): string[] {
  const raw = process.env.ALLOWED_EMAIL_DOMAINS?.trim();
  if (!raw) return DEFAULT_ALLOWED_DOMAINS;
  return raw.split(',').map((d) => d.trim().toLowerCase()).filter(Boolean);
}

export function isAllowedEmailDomain(email: string): boolean {
  const domains = allowedEmailDomains();
  if (domains.includes('*')) return true;
  const domain = normalizeEmail(email).split('@')[1] ?? '';
  return domains.includes(domain);
}

function newProxyKey(): string {
  return `bilvantisllmapi-${crypto.randomBytes(24).toString('hex')}`;
}

export function userCount(): number {
  const row = getDb().prepare('SELECT COUNT(*) AS c FROM users').get() as { c: number };
  return row.c;
}

export function adminCount(): number {
  const row = getDb().prepare("SELECT COUNT(*) AS c FROM users WHERE role = 'admin'").get() as { c: number };
  return row.c;
}

/**
 * Create a user with their own proxy key. Throws { code: 'email_taken' } if the
 * email already exists. The very first account is forced to 'admin' regardless
 * of the requested role, so an install is never left without an admin.
 */
export function createUser(email: string, password: string, role: Role = 'member'): SessionUser {
  const db = getDb();
  const normalized = normalizeEmail(email);
  const existing = db.prepare('SELECT id FROM users WHERE email = ?').get(normalized);
  if (existing) {
    const err = new Error('An account with that email already exists') as any;
    err.code = 'email_taken';
    throw err;
  }
  const effectiveRole: Role = userCount() === 0 ? 'admin' : role;
  const result = db
    .prepare('INSERT INTO users (email, password_hash, role, proxy_key) VALUES (?, ?, ?, ?)')
    .run(normalized, hashPassword(password), effectiveRole, newProxyKey());
  return { userId: Number(result.lastInsertRowid), email: normalized, role: effectiveRole };
}

/** Verify credentials. Returns the user on success, null on failure. */
export function verifyCredentials(email: string, password: string): SessionUser | null {
  const db = getDb();
  const row = db.prepare('SELECT id, email, role, password_hash FROM users WHERE email = ?')
    .get(normalizeEmail(email)) as { id: number; email: string; role: Role; password_hash: string } | undefined;
  if (!row) return null;
  if (!verifyPassword(password, row.password_hash)) return null;
  return { userId: row.id, email: row.email, role: row.role };
}

/** Mint a session and return the raw token (only the hash is persisted). */
export function createSession(userId: number): string {
  const token = crypto.randomBytes(32).toString('hex');
  getDb().prepare('INSERT INTO sessions (token_hash, user_id, expires_at_ms) VALUES (?, ?, ?)')
    .run(sha256(token), userId, Date.now() + SESSION_TTL_MS);
  return token;
}

/** Resolve a session token to its user, or null if missing/expired. */
export function validateSession(token: string | undefined | null): SessionUser | null {
  if (!token) return null;
  const db = getDb();
  const row = db.prepare(`
    SELECT s.user_id, s.expires_at_ms, u.email, u.role
    FROM sessions s JOIN users u ON u.id = s.user_id
    WHERE s.token_hash = ?
  `).get(sha256(token)) as { user_id: number; expires_at_ms: number; email: string; role: Role } | undefined;
  if (!row) return null;
  if (row.expires_at_ms < Date.now()) {
    db.prepare('DELETE FROM sessions WHERE token_hash = ?').run(sha256(token));
    return null;
  }
  return { userId: row.user_id, email: row.email, role: row.role };
}

export function deleteSession(token: string | undefined | null): void {
  if (!token) return;
  getDb().prepare('DELETE FROM sessions WHERE token_hash = ?').run(sha256(token));
}

// ── Proxy-key management (per-user /v1 credential) ─────────────────────────

/** Resolve a /v1 proxy key to its owning user, or null. Used by proxy auth. */
export function getUserByProxyKey(key: string | undefined | null): SessionUser | null {
  if (!key) return null;
  const row = getDb()
    .prepare('SELECT id, email, role FROM users WHERE proxy_key = ?')
    .get(key.trim()) as { id: number; email: string; role: Role } | undefined;
  return row ? { userId: row.id, email: row.email, role: row.role } : null;
}

/** The caller's own proxy key (for display in the dashboard). */
export function getProxyKey(userId: number): string | null {
  const row = getDb().prepare('SELECT proxy_key FROM users WHERE id = ?').get(userId) as { proxy_key: string | null } | undefined;
  return row?.proxy_key ?? null;
}

/** Rotate a user's proxy key and return the new value. */
export function regenerateProxyKey(userId: number): string {
  const key = newProxyKey();
  getDb().prepare('UPDATE users SET proxy_key = ? WHERE id = ?').run(key, userId);
  return key;
}

// ── User administration (admin-only surface) ───────────────────────────────

export function listUsers(): UserRecord[] {
  return getDb().prepare(`
    SELECT u.id, u.email, u.role, u.created_at AS createdAt,
           (SELECT COUNT(*) FROM api_keys k WHERE k.user_id = u.id) AS hasKeys
    FROM users u
    ORDER BY u.id ASC
  `).all() as UserRecord[];
}

export function getUser(id: number): UserRecord | null {
  const row = getDb().prepare(`
    SELECT u.id, u.email, u.role, u.created_at AS createdAt,
           (SELECT COUNT(*) FROM api_keys k WHERE k.user_id = u.id) AS hasKeys
    FROM users u WHERE u.id = ?
  `).get(id) as UserRecord | undefined;
  return row ?? null;
}

/**
 * Delete a user (and — via ON DELETE CASCADE — their sessions and provider
 * keys). Throws { code } for guard violations the route surfaces as 4xx.
 */
export function deleteUser(id: number): void {
  const db = getDb();
  const user = db.prepare('SELECT id, role FROM users WHERE id = ?').get(id) as { id: number; role: Role } | undefined;
  if (!user) {
    const err = new Error('User not found') as any;
    err.code = 'not_found';
    throw err;
  }
  if (user.role === 'admin' && adminCount() <= 1) {
    const err = new Error('Cannot delete the last admin') as any;
    err.code = 'last_admin';
    throw err;
  }
  db.prepare('DELETE FROM users WHERE id = ?').run(id);
}
