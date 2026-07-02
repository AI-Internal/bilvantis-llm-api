import crypto from 'crypto';
import type Database from 'better-sqlite3';

/**
 * Multi-tenant (isolated per-user) support.
 *
 * The app was single-user: one dashboard account, one global proxy key
 * (`settings.unified_api_key`), and one shared pool of provider keys / usage.
 * This migration makes the privacy-sensitive data per-user:
 *
 *   - `users` gains `proxy_key` (each user's own /v1 credential) and `role`
 *     ('admin' curates the shared catalog/routing + manages users; 'member'
 *     just brings their own keys). The first existing user becomes the admin.
 *   - `api_keys` gains `user_id` — provider keys are owned by a single user.
 *     Existing keys are backfilled to the admin.
 *   - `requests` gains `user_id` for per-user analytics; backfilled from the
 *     owning key where resolvable.
 *
 * The shared model catalog (`models`, `quirks`, `embedding_models`,
 * `media_models`, tombstones) and routing config (`fallback_config`,
 * `profiles`, `routing_strategy`) stay global and admin-managed. Rate-limit and
 * quota tables stay keyed by `key_id`; since a key now belongs to exactly one
 * user, they are isolated transitively.
 */

function columnExists(db: Database.Database, table: string, column: string): boolean {
  const rows = db.prepare(`PRAGMA table_info(${table})`).all() as Array<{ name: string }>;
  return rows.some((r) => r.name === column);
}

function newProxyKey(): string {
  return `bilvantisllmapi-${crypto.randomBytes(24).toString('hex')}`;
}

export function up(db: Database.Database): void {
  // ── users: role + per-user proxy key ────────────────────────────────────
  if (!columnExists(db, 'users', 'role')) {
    db.prepare(`ALTER TABLE users ADD COLUMN role TEXT NOT NULL DEFAULT 'member'`).run();
  }
  if (!columnExists(db, 'users', 'proxy_key')) {
    db.prepare(`ALTER TABLE users ADD COLUMN proxy_key TEXT`).run();
  }

  // The earliest account (lowest id) is the admin/owner of this install.
  const firstUser = db
    .prepare('SELECT id FROM users ORDER BY id ASC LIMIT 1')
    .get() as { id: number } | undefined;
  if (firstUser) {
    db.prepare("UPDATE users SET role = 'admin' WHERE id = ?").run(firstUser.id);
  }

  // Give the admin the existing global unified key (so already-configured
  // clients keep working), then mint a fresh key for every other user.
  const legacyUnified = db
    .prepare("SELECT value FROM settings WHERE key = 'unified_api_key'")
    .get() as { value: string } | undefined;
  if (firstUser && legacyUnified?.value) {
    db.prepare('UPDATE users SET proxy_key = ? WHERE id = ? AND proxy_key IS NULL').run(
      legacyUnified.value,
      firstUser.id,
    );
  }
  const needKey = db.prepare('SELECT id FROM users WHERE proxy_key IS NULL').all() as { id: number }[];
  const setKey = db.prepare('UPDATE users SET proxy_key = ? WHERE id = ?');
  for (const u of needKey) setKey.run(newProxyKey(), u.id);

  db.prepare('CREATE UNIQUE INDEX IF NOT EXISTS idx_users_proxy_key ON users(proxy_key)').run();

  // ── api_keys: owner ──────────────────────────────────────────────────────
  if (!columnExists(db, 'api_keys', 'user_id')) {
    db.prepare('ALTER TABLE api_keys ADD COLUMN user_id INTEGER REFERENCES users(id) ON DELETE CASCADE').run();
  }
  if (firstUser) {
    db.prepare('UPDATE api_keys SET user_id = ? WHERE user_id IS NULL').run(firstUser.id);
  }
  db.prepare('CREATE INDEX IF NOT EXISTS idx_api_keys_user ON api_keys(user_id)').run();

  // Safety net: if a key is ever inserted without an owner, attach it to the
  // first (admin) user rather than leaving it ownerless (unroutable, invisible).
  // Every application insert now passes user_id explicitly, so in normal
  // operation this never fires — it only backstops direct/legacy inserts.
  db.prepare(`
    CREATE TRIGGER IF NOT EXISTS api_keys_default_owner
    AFTER INSERT ON api_keys
    WHEN NEW.user_id IS NULL
    BEGIN
      UPDATE api_keys SET user_id = (SELECT id FROM users ORDER BY id ASC LIMIT 1)
       WHERE id = NEW.id;
    END
  `).run();

  // ── requests: per-user analytics ─────────────────────────────────────────
  if (!columnExists(db, 'requests', 'user_id')) {
    db.prepare('ALTER TABLE requests ADD COLUMN user_id INTEGER').run();
    // Backfill from the owning key where the key still exists.
    db.prepare(`
      UPDATE requests
         SET user_id = (SELECT k.user_id FROM api_keys k WHERE k.id = requests.key_id)
       WHERE user_id IS NULL AND key_id IS NOT NULL
    `).run();
  }
  db.prepare('CREATE INDEX IF NOT EXISTS idx_requests_user ON requests(user_id, created_at)').run();
}

export function down(db: Database.Database): void {
  // SQLite can't drop columns pre-3.35 without a table rebuild; these indexes
  // are the reversible surface. Columns are left in place (harmless, defaulted).
  db.prepare('DROP TRIGGER IF EXISTS api_keys_default_owner').run();
  db.prepare('DROP INDEX IF EXISTS idx_requests_user').run();
  db.prepare('DROP INDEX IF EXISTS idx_api_keys_user').run();
  db.prepare('DROP INDEX IF EXISTS idx_users_proxy_key').run();
}
