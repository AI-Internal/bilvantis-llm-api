import { describe, it, expect, beforeAll } from 'vitest';
import type { Express } from 'express';
import { createApp } from '../../app.js';
import { initDb } from '../../db/index.js';

// End-to-end tenant isolation: two users, each with their own login, proxy key,
// provider keys, and usage. Exercises the real HTTP surface (auth → users →
// keys → settings) rather than internals.
async function http(app: Express, method: string, path: string, body?: any, token?: string) {
  const server = app.listen(0);
  const { port } = server.address() as any;
  const res = await fetch(`http://127.0.0.1:${port}${path}`, {
    method,
    headers: {
      ...(body ? { 'Content-Type': 'application/json' } : {}),
      ...(token ? { Authorization: `Bearer ${token}` } : {}),
    },
    body: body ? JSON.stringify(body) : undefined,
  });
  const text = await res.text();
  server.close();
  let json: any = null;
  try { json = JSON.parse(text); } catch { /* non-JSON */ }
  return { status: res.status, body: json };
}

describe('multi-tenant isolation', () => {
  let app: Express;
  let adminToken = '';
  let memberToken = '';

  beforeAll(async () => {
    process.env.ENCRYPTION_KEY = '0'.repeat(64);
    initDb(':memory:');
    app = createApp();

    // First account = admin (via first-run setup).
    const setup = await http(app, 'POST', '/api/auth/setup', { email: 'admin@bilvantis.io', password: 'password123' });
    expect(setup.status).toBe(201);
    expect(setup.body.role).toBe('admin');
    adminToken = setup.body.token;

    // Admin adds a member.
    const created = await http(app, 'POST', '/api/users', { email: 'member@bilvantis.io', password: 'password123' }, adminToken);
    expect(created.status).toBe(201);
    expect(created.body.user.role).toBe('member');

    const login = await http(app, 'POST', '/api/auth/login', { email: 'member@bilvantis.io', password: 'password123' }, undefined);
    expect(login.status).toBe(200);
    memberToken = login.body.token;
  });

  it('gives each user a distinct proxy key', async () => {
    const a = await http(app, 'GET', '/api/settings/api-key', undefined, adminToken);
    const b = await http(app, 'GET', '/api/settings/api-key', undefined, memberToken);
    expect(a.body.apiKey).toMatch(/^bilvantisllmapi-/);
    expect(b.body.apiKey).toMatch(/^bilvantisllmapi-/);
    expect(a.body.apiKey).not.toBe(b.body.apiKey);
  });

  it('scopes provider keys per user — one user never sees another\'s', async () => {
    const add = await http(app, 'POST', '/api/keys', { platform: 'groq', label: 'admins', key: 'gsk_admin_secret' }, adminToken);
    expect(add.status).toBe(201);

    const adminKeys = await http(app, 'GET', '/api/keys', undefined, adminToken);
    expect(adminKeys.body.some((k: any) => k.platform === 'groq')).toBe(true);

    const memberKeys = await http(app, 'GET', '/api/keys', undefined, memberToken);
    expect(memberKeys.body.length).toBe(0);
  });

  it('lets each user manage only their own keys (delete is owner-scoped)', async () => {
    const add = await http(app, 'POST', '/api/keys', { platform: 'cerebras', label: 'a', key: 'csk_admin' }, adminToken);
    const keyId = add.body.id;
    // Member cannot delete the admin's key (reads as not-found, not forbidden).
    const memberDelete = await http(app, 'DELETE', `/api/keys/${keyId}`, undefined, memberToken);
    expect(memberDelete.status).toBe(404);
    // Admin still has it.
    const adminKeys = await http(app, 'GET', '/api/keys', undefined, adminToken);
    expect(adminKeys.body.some((k: any) => k.id === keyId)).toBe(true);
  });

  it('gates team management to admins', async () => {
    expect((await http(app, 'GET', '/api/users', undefined, memberToken)).status).toBe(403);
    expect((await http(app, 'GET', '/api/users', undefined, adminToken)).status).toBe(200);
  });

  it('scopes analytics per user (member sees none of the admin traffic)', async () => {
    const memberSummary = await http(app, 'GET', '/api/analytics/summary', undefined, memberToken);
    expect(memberSummary.status).toBe(200);
    expect(memberSummary.body.totalRequests).toBe(0);
  });
});
