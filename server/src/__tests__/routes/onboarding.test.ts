import { describe, it, expect, afterEach, vi } from 'vitest';
import type { Express } from 'express';
import { createApp } from '../../app.js';
import { initDb, getDb } from '../../db/index.js';
import { getAllProviders } from '../../providers/index.js';
import { provisionFreeDefaults } from '../../services/free-defaults.js';

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

const KEYLESS = getAllProviders().filter((p) => p.keyless).map((p) => p.platform);

function freshApp(): Express {
  process.env.ENCRYPTION_KEY = '0'.repeat(64);
  initDb(':memory:');
  return createApp();
}

describe('free keyless defaults on signup', () => {
  afterEach(() => { delete process.env.DISABLE_FREE_DEFAULTS; vi.unstubAllGlobals(); });

  it('gives a new account a keyless key for every keyless provider', async () => {
    delete process.env.DISABLE_FREE_DEFAULTS;
    const app = freshApp();
    const setup = await http(app, 'POST', '/api/auth/setup', { email: 'admin@bilvantis.io', password: 'password123' });
    expect(setup.status).toBe(201);

    const keys = await http(app, 'GET', '/api/keys', undefined, setup.body.token);
    const platforms = new Set(keys.body.map((k: any) => k.platform));
    expect(KEYLESS.length).toBeGreaterThan(0);
    for (const p of KEYLESS) expect(platforms.has(p)).toBe(true);
    expect(keys.body.length).toBe(KEYLESS.length); // only the free defaults, nothing else
  });

  it('provisions nothing when DISABLE_FREE_DEFAULTS=1', async () => {
    process.env.DISABLE_FREE_DEFAULTS = '1';
    const app = freshApp();
    const setup = await http(app, 'POST', '/api/auth/setup', { email: 'admin@bilvantis.io', password: 'password123' });
    const keys = await http(app, 'GET', '/api/keys', undefined, setup.body.token);
    expect(keys.body.length).toBe(0);
  });

  it('is idempotent — re-provisioning adds nothing', () => {
    delete process.env.DISABLE_FREE_DEFAULTS;
    freshApp();
    const db = getDb();
    const info = db.prepare(
      "INSERT INTO users (email, password_hash, role, proxy_key) VALUES ('x@bilvantis.io', 'h', 'admin', 'bilvantisllmapi-x')",
    ).run();
    const userId = Number(info.lastInsertRowid);
    expect(provisionFreeDefaults(db, userId)).toBe(KEYLESS.length);
    expect(provisionFreeDefaults(db, userId)).toBe(0);
  });
});

describe('OpenRouter OAuth connect', () => {
  afterEach(() => { delete process.env.DISABLE_FREE_DEFAULTS; vi.unstubAllGlobals(); });

  it('exchanges the code for a key and stores it on the caller only', async () => {
    process.env.DISABLE_FREE_DEFAULTS = '1'; // clean baseline
    const app = freshApp();
    const admin = await http(app, 'POST', '/api/auth/setup', { email: 'admin@bilvantis.io', password: 'password123' });
    const member = await http(app, 'POST', '/api/auth/register', { email: 'member@bilvantis.io', password: 'password123' });

    // Stub only OpenRouter's token exchange; let the test's own HTTP calls
    // (to the app server) go through the real fetch.
    const realFetch = globalThis.fetch;
    vi.stubGlobal('fetch', vi.fn(async (url: any, init: any) =>
      String(url).includes('openrouter.ai')
        ? { ok: true, json: async () => ({ key: 'sk-or-connected' }) }
        : realFetch(url, init),
    ) as any);

    const connect = await http(app, 'POST', '/api/keys/openrouter/oauth', { code: 'abc', codeVerifier: 'v'.repeat(48) }, admin.body.token);
    expect(connect.status).toBe(201);
    expect(connect.body.platform).toBe('openrouter');

    const adminKeys = await http(app, 'GET', '/api/keys', undefined, admin.body.token);
    expect(adminKeys.body.some((k: any) => k.platform === 'openrouter')).toBe(true);
    // The member never gets the admin's connected key.
    const memberKeys = await http(app, 'GET', '/api/keys', undefined, member.body.token);
    expect(memberKeys.body.some((k: any) => k.platform === 'openrouter')).toBe(false);
  });

  it('surfaces a failed exchange as 502', async () => {
    process.env.DISABLE_FREE_DEFAULTS = '1';
    const app = freshApp();
    const admin = await http(app, 'POST', '/api/auth/setup', { email: 'admin@bilvantis.io', password: 'password123' });
    const realFetch = globalThis.fetch;
    vi.stubGlobal('fetch', vi.fn(async (url: any, init: any) =>
      String(url).includes('openrouter.ai')
        ? { ok: false, json: async () => ({ error: 'bad code' }) }
        : realFetch(url, init),
    ) as any);
    const connect = await http(app, 'POST', '/api/keys/openrouter/oauth', { code: 'x', codeVerifier: 'v'.repeat(48) }, admin.body.token);
    expect(connect.status).toBe(502);
  });
});
