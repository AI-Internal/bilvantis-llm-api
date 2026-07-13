import { Router } from 'express';
import type { Request, Response } from 'express';
import { z } from 'zod';
import { getDb } from '../db/index.js';
import { hasProvider } from '../providers/index.js';
import { deleteUnusedCustomEndpointKey } from '../lib/custom-provider-cleanup.js';
import {
  isCatalogManagedModel,
  recordCatalogModelTombstone,
  upsertModelOverrides,
  type ModelOverridePatch,
} from '../services/model-state.js';
import type { SessionUser } from '../services/auth.js';

export const modelsRouter = Router();

// The dashboard session user (requireAuth gates this router). Custom models are
// private to the user who owns the key they're bound to; catalog models
// (key_id IS NULL) are the shared reference catalog visible to everyone.
function uid(req: Request): number {
  return (req as Request & { user?: SessionUser }).user!.userId;
}

// SQL predicate: keep shared catalog rows (key_id NULL) plus the caller's own
// custom rows; hide every other user's custom models. `alias` is the models
// table alias in the query.
function ownedModelsFilter(alias: string): string {
  return `(${alias}.key_id IS NULL OR ${alias}.key_id IN (SELECT id FROM api_keys WHERE user_id = ?))`;
}

// A custom model (key_id set) may only be mutated by the user who owns its key,
// so one user can't edit/delete another's private models. Catalog models
// (key_id NULL) are shared config and not gated here.
function mayMutateModel(req: Request, keyId: number | null): boolean {
  if (keyId == null) return true;
  const owns = getDb().prepare('SELECT 1 FROM api_keys WHERE id = ? AND user_id = ?').get(keyId, uid(req));
  return Boolean(owns);
}

const modelUpdateSchema = z.object({
  displayName: z.string().min(1).max(200).optional(),
  intelligenceRank: z.number().int().min(1).max(1000).optional(),
  speedRank: z.number().int().min(1).max(1000).optional(),
  sizeLabel: z.string().min(1).max(40).optional(),
  rpmLimit: z.number().int().positive().nullable().optional(),
  rpdLimit: z.number().int().positive().nullable().optional(),
  tpmLimit: z.number().int().positive().nullable().optional(),
  tpdLimit: z.number().int().positive().nullable().optional(),
  monthlyTokenBudget: z.string().max(80).optional(),
  contextWindow: z.number().int().positive().nullable().optional(),
  enabled: z.boolean().optional(),
  supportsVision: z.boolean().optional(),
  supportsTools: z.boolean().optional(),
  fallbackEnabled: z.boolean().optional(),
}).strict();

const MODEL_FIELD_COLUMNS: Record<keyof ModelOverridePatch | 'enabled', string> = {
  displayName: 'display_name',
  intelligenceRank: 'intelligence_rank',
  speedRank: 'speed_rank',
  sizeLabel: 'size_label',
  rpmLimit: 'rpm_limit',
  rpdLimit: 'rpd_limit',
  tpmLimit: 'tpm_limit',
  tpdLimit: 'tpd_limit',
  monthlyTokenBudget: 'monthly_token_budget',
  contextWindow: 'context_window',
  supportsVision: 'supports_vision',
  supportsTools: 'supports_tools',
  enabled: 'enabled',
};

type ModelRow = {
  id: number;
  platform: string;
  model_id: string;
  key_id: number | null;
};

function dbValue(key: keyof typeof MODEL_FIELD_COLUMNS, value: unknown): unknown {
  if (key === 'enabled' || key === 'supportsVision' || key === 'supportsTools') return value ? 1 : 0;
  return value;
}

function fetchModelRow(id: number): ModelRow | undefined {
  return getDb()
    .prepare('SELECT id, platform, model_id, key_id FROM models WHERE id = ?')
    .get(id) as ModelRow | undefined;
}

modelsRouter.delete('/custom/:id', (req: Request, res: Response) => {
  const id = Number(req.params.id);
  if (!Number.isInteger(id)) {
    res.status(400).json({ error: { message: 'Invalid id' } });
    return;
  }

  const db = getDb();
  const row = db.prepare("SELECT id, key_id FROM models WHERE id = ? AND platform = 'custom'").get(id) as { id: number; key_id: number | null } | undefined;
  if (!row || !mayMutateModel(req, row.key_id)) {
    res.status(404).json({ error: { message: `Unknown custom model ${id}` } });
    return;
  }

  const remove = db.transaction(() => {
    db.prepare('DELETE FROM fallback_config WHERE model_db_id = ?').run(id);
    db.prepare("DELETE FROM models WHERE id = ? AND platform = 'custom'").run(id);
    deleteUnusedCustomEndpointKey(db, row.key_id);
  });
  remove();
  res.json({ success: true });
});

modelsRouter.patch('/:id', (req: Request, res: Response) => {
  const id = Number(req.params.id);
  if (!Number.isInteger(id)) {
    res.status(400).json({ error: { message: 'Invalid id' } });
    return;
  }

  const parsed = modelUpdateSchema.safeParse(req.body);
  if (!parsed.success) {
    res.status(400).json({ error: { message: parsed.error.errors.map(e => e.message).join(', ') } });
    return;
  }

  const db = getDb();
  const row = fetchModelRow(id);
  if (!row || !mayMutateModel(req, row.key_id)) {
    res.status(404).json({ error: { message: `Unknown model ${id}` } });
    return;
  }

  const modelPatch: Partial<typeof parsed.data> = { ...parsed.data };
  delete modelPatch.fallbackEnabled;
  const modelKeys = Object.keys(modelPatch) as Array<keyof typeof modelPatch>;
  if (modelKeys.length === 0 && parsed.data.fallbackEnabled === undefined) {
    res.status(400).json({ error: { message: 'No model fields provided' } });
    return;
  }

  const applyUpdate = db.transaction(() => {
    if (modelKeys.length > 0) {
      const assignments: string[] = [];
      const values: unknown[] = [];
      for (const key of modelKeys) {
        assignments.push(`${MODEL_FIELD_COLUMNS[key as keyof typeof MODEL_FIELD_COLUMNS]} = ?`);
        values.push(dbValue(key as keyof typeof MODEL_FIELD_COLUMNS, modelPatch[key]));
      }
      values.push(id);
      db.prepare(`UPDATE models SET ${assignments.join(', ')} WHERE id = ?`).run(...values);

      if (isCatalogManagedModel(row)) {
        const overridePatch: ModelOverridePatch = {};
        for (const key of [
          'displayName', 'intelligenceRank', 'speedRank', 'sizeLabel',
          'rpmLimit', 'rpdLimit', 'tpmLimit', 'tpdLimit',
          'monthlyTokenBudget', 'contextWindow', 'supportsVision', 'supportsTools',
        ] as const) {
          if (Object.prototype.hasOwnProperty.call(modelPatch, key)) {
            overridePatch[key] = modelPatch[key] as never;
          }
        }
        upsertModelOverrides(db, row.platform, row.model_id, overridePatch);
      }
    }

    if (parsed.data.fallbackEnabled !== undefined) {
      db.prepare('UPDATE fallback_config SET enabled = ? WHERE model_db_id = ?')
        .run(parsed.data.fallbackEnabled ? 1 : 0, id);
    }
  });
  applyUpdate();

  res.json({ success: true, id });
});

modelsRouter.delete('/:id', (req: Request, res: Response) => {
  const id = Number(req.params.id);
  if (!Number.isInteger(id)) {
    res.status(400).json({ error: { message: 'Invalid id' } });
    return;
  }

  const db = getDb();
  const row = fetchModelRow(id);
  if (!row || !mayMutateModel(req, row.key_id)) {
    res.status(404).json({ error: { message: `Unknown model ${id}` } });
    return;
  }

  const remove = db.transaction(() => {
    if (isCatalogManagedModel(row)) {
      recordCatalogModelTombstone(db, 'chat', row.platform, row.model_id);
    }
    db.prepare('DELETE FROM fallback_config WHERE model_db_id = ?').run(id);
    db.prepare('DELETE FROM models WHERE id = ?').run(id);
    if (row.platform === 'custom') deleteUnusedCustomEndpointKey(db, row.key_id);
  });
  remove();

  res.json({ success: true, tombstoned: isCatalogManagedModel(row) });
});

// List all models with availability info
modelsRouter.get('/', (req: Request, res: Response) => {
  const db = getDb();
  const userId = uid(req);
  const models = db.prepare(`
    SELECT m.*, fc.priority, fc.enabled as fallback_enabled,
           mo.overrides_json IS NOT NULL AS has_overrides,
           ak.label AS key_label
    FROM models m
    LEFT JOIN fallback_config fc ON fc.model_db_id = m.id
    LEFT JOIN model_overrides mo ON mo.platform = m.platform AND mo.model_id = m.model_id
    LEFT JOIN api_keys ak ON ak.id = m.key_id
    WHERE ${ownedModelsFilter('m')}
    ORDER BY COALESCE(fc.priority, m.intelligence_rank) ASC
  `).all(userId) as any[];

  // Count the caller's OWN keys per platform (availability must reflect this
  // user's keys, not the whole team's).
  const keyCounts = db.prepare(`
    SELECT platform, COUNT(*) as count
    FROM api_keys
    WHERE enabled = 1 AND user_id = ?
    GROUP BY platform
  `).all(userId) as { platform: string; count: number }[];

  const keyCountMap = new Map(keyCounts.map(k => [k.platform, k.count]));

  const result = models.map(m => ({
    id: m.id,
    platform: m.platform,
    modelId: m.model_id,
    displayName: m.display_name,
    intelligenceRank: m.intelligence_rank,
    speedRank: m.speed_rank,
    sizeLabel: m.size_label,
    rpmLimit: m.rpm_limit,
    rpdLimit: m.rpd_limit,
    tpmLimit: m.tpm_limit,
    tpdLimit: m.tpd_limit,
    monthlyTokenBudget: m.monthly_token_budget,
    contextWindow: m.context_window,
    enabled: m.enabled === 1,
    supportsVision: m.supports_vision === 1,
    supportsTools: m.supports_tools === 1,
    priority: m.priority,
    fallbackEnabled: m.fallback_enabled === 1,
    source: m.platform === 'custom' || m.key_id != null ? 'custom' : 'catalog',
    keyId: m.key_id ?? null,
    keyLabel: m.key_label ?? null,
    hasOverrides: Boolean(m.has_overrides),
    hasProvider: hasProvider(m.platform),
    keyCount: keyCountMap.get(m.platform) ?? 0,
  }));

  res.json(result);
});
