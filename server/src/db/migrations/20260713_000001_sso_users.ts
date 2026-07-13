import type Database from 'better-sqlite3';

/**
 * Microsoft Entra ID (Azure AD) SSO support.
 *
 * Purely additive: `users` gains `auth_provider` ('password' | 'microsoft'),
 * `sso_subject` (Microsoft's `oid` claim — stable per-user identifier within a
 * tenant, survives email/UPN renames), and `sso_tenant_id`. SSO-provisioned
 * accounts still go through the existing `createUser()` insert path with a
 * random unusable password, so `password_hash` stays NOT NULL and no table
 * rebuild is needed.
 */

function columnExists(db: Database.Database, table: string, column: string): boolean {
  const rows = db.prepare(`PRAGMA table_info(${table})`).all() as Array<{ name: string }>;
  return rows.some((r) => r.name === column);
}

export function up(db: Database.Database): void {
  if (!columnExists(db, 'users', 'auth_provider')) {
    db.prepare(`ALTER TABLE users ADD COLUMN auth_provider TEXT NOT NULL DEFAULT 'password'`).run();
  }
  if (!columnExists(db, 'users', 'sso_subject')) {
    db.prepare(`ALTER TABLE users ADD COLUMN sso_subject TEXT`).run();
  }
  if (!columnExists(db, 'users', 'sso_tenant_id')) {
    db.prepare(`ALTER TABLE users ADD COLUMN sso_tenant_id TEXT`).run();
  }
  db.prepare(
    `CREATE UNIQUE INDEX IF NOT EXISTS idx_users_sso_subject ON users(sso_subject) WHERE sso_subject IS NOT NULL`,
  ).run();
}

export function down(db: Database.Database): void {
  // SQLite can't drop columns pre-3.35 without a table rebuild; the index is
  // the reversible surface. Columns are left in place (harmless, defaulted).
  db.prepare('DROP INDEX IF EXISTS idx_users_sso_subject').run();
}
