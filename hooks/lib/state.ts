// SQLite state store for the sanitiser. WAL mode + retry-on-busy so concurrent
// Claude Code sessions don't trip each other up (FR-11, R4).

import { Database } from "bun:sqlite";
import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname } from "node:path";

export const STATE_DIR = `${process.env.HOME}/.claude/safe-web-research`;
export const STATE_DB = `${STATE_DIR}/state.db`;
export const BLOCKLIST_JSON = `${process.env.HOME}/.claude/web-blocklist.json`;
export const ERROR_LOG = `${STATE_DIR}/hook-errors.log`;
export const FETCH_LOG = `${STATE_DIR}/fetch-log.jsonl`;
export const FETCH_LOG_DEBUG = `${STATE_DIR}/fetch-log-debug.jsonl`;

const SCHEMA = `
CREATE TABLE IF NOT EXISTS sessions (
  session_id TEXT PRIMARY KEY,
  web_tool_call_count INTEGER NOT NULL DEFAULT 0,
  started_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS blocklist (
  domain TEXT PRIMARY KEY,
  reason TEXT NOT NULL,
  added_at TEXT NOT NULL,
  source TEXT NOT NULL CHECK (source IN ('auto', 'user', 'session')),
  expires_at TEXT
);

CREATE TABLE IF NOT EXISTS robots_cache (
  domain TEXT PRIMARY KEY,
  fetched_at TEXT NOT NULL,
  body TEXT,
  parsed_disallow_paths TEXT,
  status_code INTEGER
);

CREATE TABLE IF NOT EXISTS fetch_log (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  url TEXT NOT NULL,
  domain TEXT NOT NULL,
  fetched_at TEXT NOT NULL,
  content_sha256 TEXT,
  original_bytes INTEGER,
  risk_signals TEXT,
  strip_diff TEXT,
  sanitiser_version TEXT,
  session_id TEXT,
  simhash TEXT,
  abort_decision INTEGER
);

CREATE INDEX IF NOT EXISTS idx_fetch_log_domain ON fetch_log(domain);
CREATE INDEX IF NOT EXISTS idx_fetch_log_session ON fetch_log(session_id, fetched_at);
CREATE INDEX IF NOT EXISTS idx_fetch_log_fetched_at ON fetch_log(fetched_at);

CREATE TABLE IF NOT EXISTS config (
  key TEXT PRIMARY KEY,
  value TEXT NOT NULL,
  updated_at TEXT NOT NULL
);
`;

let _db: Database | null = null;

export const getDb = (): Database => {
    if (_db) {
        return _db;
    }
    if (!existsSync(STATE_DIR)) {
        mkdirSync(STATE_DIR, { recursive: true });
    }
    const db = new Database(STATE_DB, { create: true });
    db.exec("PRAGMA journal_mode = WAL");
    db.exec("PRAGMA busy_timeout = 3000");
    db.exec("PRAGMA synchronous = NORMAL");
    db.exec(SCHEMA);
    try {
        db.exec("ALTER TABLE fetch_log ADD COLUMN abort_decision INTEGER");
    } catch {
        // column already exists on databases created before this migration
    }
    _db = db;
    return db;
};

export const closeDb = (): void => {
    if (_db) {
        _db.close();
        _db = null;
    }
};

export interface SessionRow {
    session_id: string;
    web_tool_call_count: number;
    started_at: string;
}

export const incrementSessionCounter = (sessionId: string): number => {
    const db = getDb();
    const now = new Date().toISOString();
    db.prepare(
        `INSERT INTO sessions (session_id, web_tool_call_count, started_at)
     VALUES (?, 1, ?)
     ON CONFLICT(session_id) DO UPDATE SET web_tool_call_count = web_tool_call_count + 1`,
    ).run(sessionId, now);
    const row = db
        .prepare(
            "SELECT web_tool_call_count FROM sessions WHERE session_id = ?",
        )
        .get(sessionId) as { web_tool_call_count: number } | undefined;
    return row?.web_tool_call_count ?? 0;
};

export interface BlocklistEntry {
    domain: string;
    reason: string;
    added_at: string;
    source: "auto" | "user" | "session";
    expires_at: string | null;
}

export const isDomainBlocked = (domain: string): BlocklistEntry | null => {
    const db = getDb();
    const row = db
        .prepare("SELECT * FROM blocklist WHERE domain = ?")
        .get(domain) as BlocklistEntry | undefined;
    if (!row) {
        return null;
    }
    if (row.expires_at && new Date(row.expires_at).getTime() < Date.now()) {
        db.prepare("DELETE FROM blocklist WHERE domain = ?").run(domain);
        return null;
    }
    return row;
};

export const addToBlocklist = (
    entry: Omit<BlocklistEntry, "added_at"> & { added_at?: string },
): void => {
    const db = getDb();
    db.prepare(
        `INSERT INTO blocklist (domain, reason, added_at, source, expires_at)
     VALUES (?, ?, ?, ?, ?)
     ON CONFLICT(domain) DO UPDATE SET reason = excluded.reason, source = excluded.source, expires_at = excluded.expires_at`,
    ).run(
        entry.domain,
        entry.reason,
        entry.added_at ?? new Date().toISOString(),
        entry.source,
        entry.expires_at,
    );
};

export interface RobotsCacheRow {
    domain: string;
    fetched_at: string;
    body: string | null;
    parsed_disallow_paths: string | null;
    status_code: number | null;
}

export const getRobotsCache = (
    domain: string,
    ttlHours: number,
): RobotsCacheRow | null => {
    const db = getDb();
    const row = db
        .prepare("SELECT * FROM robots_cache WHERE domain = ?")
        .get(domain) as RobotsCacheRow | undefined;
    if (!row) {
        return null;
    }
    const ageMs = Date.now() - new Date(row.fetched_at).getTime();
    if (ageMs > ttlHours * 3600 * 1000) {
        return null;
    }
    return row;
};

export const setRobotsCache = (row: RobotsCacheRow): void => {
    const db = getDb();
    db.prepare(
        `INSERT INTO robots_cache (domain, fetched_at, body, parsed_disallow_paths, status_code)
     VALUES (?, ?, ?, ?, ?)
     ON CONFLICT(domain) DO UPDATE SET
       fetched_at = excluded.fetched_at,
       body = excluded.body,
       parsed_disallow_paths = excluded.parsed_disallow_paths,
       status_code = excluded.status_code`,
    ).run(
        row.domain,
        row.fetched_at,
        row.body,
        row.parsed_disallow_paths,
        row.status_code,
    );
};

export interface FetchLogRow {
    url: string;
    domain: string;
    fetched_at: string;
    content_sha256: string | null;
    original_bytes: number | null;
    risk_signals: string;
    strip_diff: string;
    sanitiser_version: string;
    session_id: string | null;
    simhash: string | null;
    abort_decision: boolean | null;
}

export const insertFetchLog = (row: FetchLogRow): void => {
    const db = getDb();
    const abortInt =
        row.abort_decision === null ? null : row.abort_decision ? 1 : 0;
    db.prepare(
        `INSERT INTO fetch_log
       (url, domain, fetched_at, content_sha256, original_bytes, risk_signals, strip_diff, sanitiser_version, session_id, simhash, abort_decision)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
    ).run(
        row.url,
        row.domain,
        row.fetched_at,
        row.content_sha256,
        row.original_bytes,
        row.risk_signals,
        row.strip_diff,
        row.sanitiser_version,
        row.session_id,
        row.simhash,
        abortInt,
    );
};

export const recentSessionFetches = (
    sessionId: string,
    domain: string,
    withinMinutes: number,
): { simhash: string | null; fetched_at: string; url: string }[] => {
    const db = getDb();
    const cutoff = new Date(
        Date.now() - withinMinutes * 60 * 1000,
    ).toISOString();
    return db
        .prepare(
            `SELECT simhash, fetched_at, url FROM fetch_log
       WHERE session_id = ? AND domain = ? AND fetched_at >= ?
       ORDER BY fetched_at DESC LIMIT 200`,
        )
        .all(sessionId, domain, cutoff) as {
        simhash: string | null;
        fetched_at: string;
        url: string;
    }[];
};

export const distinctPathsForDomain = (
    sessionId: string,
    domain: string,
    withinMinutes: number,
): number => {
    const db = getDb();
    const cutoff = new Date(
        Date.now() - withinMinutes * 60 * 1000,
    ).toISOString();
    const row = db
        .prepare(
            `SELECT COUNT(DISTINCT url) AS n FROM fetch_log
       WHERE session_id = ? AND domain = ? AND fetched_at >= ?`,
        )
        .get(sessionId, domain, cutoff) as { n: number } | undefined;
    return row?.n ?? 0;
};

// Reconcile JSON ↔ SQLite blocklist. User edits to JSON take precedence (FR-12).
export const reconcileBlocklistJson = (): void => {
    const db = getDb();
    if (!existsSync(BLOCKLIST_JSON)) {
        const userRows = db
            .prepare(
                "SELECT domain, reason, added_at, source, expires_at FROM blocklist WHERE source != 'session'",
            )
            .all() as BlocklistEntry[];
        writeFileSync(
            BLOCKLIST_JSON,
            JSON.stringify({ version: 1, entries: userRows }, null, 2),
        );
        return;
    }
    try {
        const raw = readFileSync(BLOCKLIST_JSON, "utf8");
        const parsed = JSON.parse(raw) as {
            version?: number;
            entries?: BlocklistEntry[];
        };
        if (!parsed.entries) {
            return;
        }
        db.transaction(() => {
            db.prepare("DELETE FROM blocklist WHERE source = 'user'").run();
            for (const entry of parsed.entries!) {
                db.prepare(
                    `INSERT INTO blocklist (domain, reason, added_at, source, expires_at)
           VALUES (?, ?, ?, 'user', ?)
           ON CONFLICT(domain) DO UPDATE SET reason = excluded.reason, source = 'user', expires_at = excluded.expires_at`,
                ).run(
                    entry.domain,
                    entry.reason,
                    entry.added_at,
                    entry.expires_at,
                );
            }
        })();
    } catch {
        // JSON malformed — leave SQLite as the source of truth
    }
};

export const ensureStateDir = (): void => {
    if (!existsSync(STATE_DIR)) {
        mkdirSync(STATE_DIR, { recursive: true });
    }
    const errDir = dirname(ERROR_LOG);
    if (!existsSync(errDir)) {
        mkdirSync(errDir, { recursive: true });
    }
};
