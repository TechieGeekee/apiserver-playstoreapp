import { Pool } from "pg";

let pool: Pool | null = null;

function getPool(): Pool | null {
  // Prefer NEON_DATABASE_URL (external, independent of Replit) if set.
  // Falls back to DATABASE_URL (Replit-provisioned) for local dev.
  const connectionString = process.env.NEON_DATABASE_URL || process.env.DATABASE_URL;
  if (!connectionString) return null;
  if (!pool) {
    pool = new Pool({
      connectionString,
      ssl: { rejectUnauthorized: false },
      max: 10,
      idleTimeoutMillis: 30000,
      connectionTimeoutMillis: 5000,
    });
    pool.on("error", (err) => {
      console.error("[DB Cache] Pool error:", err.message);
    });
  }
  return pool;
}

// ── Search cache ────────────────────────────────────────────────────────────

export interface SearchCacheEntry {
  apps: unknown[];
  category: string;
  intent: string;
}

export async function getSearchCache(key: string): Promise<SearchCacheEntry | null> {
  const db = getPool();
  if (!db) return null;
  try {
    const result = await db.query(
      "SELECT apps_json, category, intent FROM search_cache WHERE cache_key = $1 AND expires_at > NOW()",
      [key]
    );
    if (result.rows.length === 0) return null;
    const row = result.rows[0];
    return { apps: JSON.parse(row.apps_json), category: row.category, intent: row.intent };
  } catch (err: any) {
    console.error("[DB Cache] getSearchCache error:", err.message);
    return null;
  }
}

export async function setSearchCache(
  key: string,
  entry: SearchCacheEntry,
  ttlHours = 6
): Promise<void> {
  const db = getPool();
  if (!db) return;
  try {
    await db.query(
      `INSERT INTO search_cache (cache_key, category, intent, apps_json, expires_at)
       VALUES ($1, $2, $3, $4, NOW() + INTERVAL '${ttlHours} hours')
       ON CONFLICT (cache_key) DO UPDATE
         SET category = EXCLUDED.category,
             intent = EXCLUDED.intent,
             apps_json = EXCLUDED.apps_json,
             created_at = NOW(),
             expires_at = NOW() + INTERVAL '${ttlHours} hours'`,
      [key, entry.category, entry.intent, JSON.stringify(entry.apps)]
    );
  } catch (err: any) {
    console.error("[DB Cache] setSearchCache error:", err.message);
  }
}

// ── App analysis cache ───────────────────────────────────────────────────────

export async function getAppCache(key: string): Promise<unknown | null> {
  const db = getPool();
  if (!db) return null;
  try {
    const result = await db.query(
      "SELECT app_json FROM app_cache WHERE cache_key = $1 AND expires_at > NOW()",
      [key]
    );
    if (result.rows.length === 0) return null;
    return JSON.parse(result.rows[0].app_json);
  } catch (err: any) {
    console.error("[DB Cache] getAppCache error:", err.message);
    return null;
  }
}

export async function setAppCache(key: string, data: unknown, ttlHours = 12): Promise<void> {
  const db = getPool();
  if (!db) return;
  try {
    await db.query(
      `INSERT INTO app_cache (cache_key, app_json, expires_at)
       VALUES ($1, $2, NOW() + INTERVAL '${ttlHours} hours')
       ON CONFLICT (cache_key) DO UPDATE
         SET app_json = EXCLUDED.app_json,
             created_at = NOW(),
             expires_at = NOW() + INTERVAL '${ttlHours} hours'`,
      [key, JSON.stringify(data)]
    );
  } catch (err: any) {
    console.error("[DB Cache] setAppCache error:", err.message);
  }
}

// ── Play Store cache ─────────────────────────────────────────────────────────

export async function getPlayStoreCache(packageId: string): Promise<unknown | null> {
  const db = getPool();
  if (!db) return null;
  try {
    const result = await db.query(
      "SELECT data_json FROM play_store_cache WHERE package_id = $1 AND expires_at > NOW()",
      [packageId]
    );
    if (result.rows.length === 0) return null;
    return JSON.parse(result.rows[0].data_json);
  } catch (err: any) {
    console.error("[DB Cache] getPlayStoreCache error:", err.message);
    return null;
  }
}

export async function setPlayStoreCache(packageId: string, data: unknown, ttlHours = 24): Promise<void> {
  const db = getPool();
  if (!db) return;
  try {
    await db.query(
      `INSERT INTO play_store_cache (package_id, data_json, expires_at)
       VALUES ($1, $2, NOW() + INTERVAL '${ttlHours} hours')
       ON CONFLICT (package_id) DO UPDATE
         SET data_json = EXCLUDED.data_json,
             created_at = NOW(),
             expires_at = NOW() + INTERVAL '${ttlHours} hours'`,
      [packageId, JSON.stringify(data)]
    );
  } catch (err: any) {
    console.error("[DB Cache] setPlayStoreCache error:", err.message);
  }
}

// ── Init (auto-create tables on first connection) ────────────────────────────

export async function initDb(): Promise<void> {
  const db = getPool();
  if (!db) return;
  try {
    await db.query(`
      CREATE TABLE IF NOT EXISTS search_cache (
        cache_key   TEXT PRIMARY KEY,
        category    TEXT NOT NULL DEFAULT '',
        intent      TEXT NOT NULL DEFAULT '',
        apps_json   TEXT NOT NULL,
        created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        expires_at  TIMESTAMPTZ NOT NULL
      );
      CREATE TABLE IF NOT EXISTS app_cache (
        cache_key   TEXT PRIMARY KEY,
        app_json    TEXT NOT NULL,
        created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        expires_at  TIMESTAMPTZ NOT NULL
      );
      CREATE TABLE IF NOT EXISTS play_store_cache (
        package_id  TEXT PRIMARY KEY,
        data_json   TEXT NOT NULL,
        created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        expires_at  TIMESTAMPTZ NOT NULL
      );
    `);
    console.info("[DB Cache] Tables ready");
  } catch (err: any) {
    console.error("[DB Cache] initDb error:", err.message);
  }
}

// ── Cleanup ──────────────────────────────────────────────────────────────────

export async function cleanupExpiredCache(): Promise<void> {
  const db = getPool();
  if (!db) return;
  try {
    await db.query("DELETE FROM search_cache WHERE expires_at < NOW()");
    await db.query("DELETE FROM app_cache WHERE expires_at < NOW()");
    await db.query("DELETE FROM play_store_cache WHERE expires_at < NOW()");
  } catch (err: any) {
    console.error("[DB Cache] cleanup error:", err.message);
  }
}
