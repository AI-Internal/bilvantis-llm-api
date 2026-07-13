import type Database from 'better-sqlite3';
import { getDb, getSetting, setSetting } from '../db/index.js';
import { getAllProviders } from '../providers/index.js';
import { encrypt } from '../lib/crypto.js';

const BACKFILL_FLAG = 'free_defaults_backfilled';

// Zero-setup onboarding: give every new user their own rows for the keyless
// providers (Kilo, Pollinations, LLM7, OVH, AI Horde) so free chat/image models
// work immediately, before they add any key of their own. Keyless providers
// route with a stored 'no-key' sentinel — the provider omits the Authorization
// header on outgoing calls (see BaseProvider.keyless / routes/keys.ts).
//
// Idempotent per user (skips platforms the user already has). Disable with
// DISABLE_FREE_DEFAULTS=1 (used by isolation tests, or for a locked-down deploy).
//
// Caveat: keyless providers are rate-limited per SERVER IP, so the whole team
// shares those limits — great for instant onboarding, not for heavy load.
export function provisionFreeDefaults(db: Database.Database, userId: number): number {
  if (process.env.DISABLE_FREE_DEFAULTS === '1') return 0;

  const keyless = getAllProviders().filter((p) => p.keyless);
  if (keyless.length === 0) return 0;

  const have = new Set(
    (db.prepare('SELECT platform FROM api_keys WHERE user_id = ?').all(userId) as { platform: string }[])
      .map((r) => r.platform),
  );
  const insert = db.prepare(
    `INSERT INTO api_keys (platform, label, encrypted_key, iv, auth_tag, status, enabled, user_id)
     VALUES (?, 'Free tier', ?, ?, ?, 'unknown', 1, ?)`,
  );

  let added = 0;
  const tx = db.transaction(() => {
    for (const p of keyless) {
      if (have.has(p.platform)) continue;
      const { encrypted, iv, authTag } = encrypt('no-key');
      insert.run(p.platform, encrypted, iv, authTag, userId);
      added++;
    }
  });
  tx();
  return added;
}

// One-time backfill so accounts created BEFORE this feature also get the free
// providers. Runs at boot; guarded by a settings flag so it only ever runs once
// (and so a user who later deletes a default doesn't get it re-added). Skipped
// entirely when DISABLE_FREE_DEFAULTS=1, leaving the flag unset so it can run
// later if re-enabled.
export function backfillFreeDefaultsOnce(): void {
  if (process.env.DISABLE_FREE_DEFAULTS === '1') return;
  const db = getDb();
  if (getSetting(BACKFILL_FLAG) === '1') return;
  const users = db.prepare('SELECT id FROM users').all() as { id: number }[];
  for (const u of users) provisionFreeDefaults(db, u.id);
  setSetting(BACKFILL_FLAG, '1');
}
