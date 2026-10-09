import { Database } from "bun:sqlite";
import { chmodSync, existsSync } from "node:fs";
import { join } from "node:path";

const SCHEMA = `
CREATE TABLE IF NOT EXISTS conversations (
  id TEXT PRIMARY KEY, title TEXT, created INTEGER, updated INTEGER, last_model TEXT,
  vault TEXT -- AES-GCM sealed VaultState
);
CREATE TABLE IF NOT EXISTS messages (
  id INTEGER PRIMARY KEY AUTOINCREMENT, conversation_id TEXT, role TEXT, content TEXT,
  model TEXT, run_id TEXT, ts INTEGER
);
CREATE INDEX IF NOT EXISTS messages_conv ON messages(conversation_id, id);
CREATE TABLE IF NOT EXISTS runs (
  id TEXT PRIMARY KEY, ts INTEGER, conversation_id TEXT, class TEXT, model TEXT, account TEXT,
  mode TEXT, pipeline TEXT, in_tok INTEGER DEFAULT 0, out_tok INTEGER DEFAULT 0, ms INTEGER,
  status TEXT, prompt_hash TEXT, explicit INTEGER DEFAULT 0
);
CREATE INDEX IF NOT EXISTS runs_account_ts ON runs(account, ts);
CREATE INDEX IF NOT EXISTS runs_hash ON runs(prompt_hash, ts);
CREATE TABLE IF NOT EXISTS quota (
  account TEXT, window TEXT, used_pct REAL, resets_at INTEGER, ts INTEGER,
  PRIMARY KEY (account, window)
);
CREATE TABLE IF NOT EXISTS cooldown (account TEXT PRIMARY KEY, until INTEGER, reason TEXT);
CREATE TABLE IF NOT EXISTS feedback (run_id TEXT, ts INTEGER, kind TEXT, value REAL);
CREATE TABLE IF NOT EXISTS scores (
  class TEXT, model TEXT, alpha REAL, beta REAL, updated INTEGER, PRIMARY KEY (class, model)
);
CREATE TABLE IF NOT EXISTS audit (
  run_id TEXT, ts INTEGER, route TEXT, account TEXT, findings TEXT, action TEXT, reasons TEXT, decided_by TEXT
);
CREATE TABLE IF NOT EXISTS workspaces (root TEXT PRIMARY KEY, added INTEGER);
CREATE TABLE IF NOT EXISTS egress (
  id INTEGER PRIMARY KEY AUTOINCREMENT, ts INTEGER, run_id TEXT, part TEXT, cwd TEXT, model TEXT, account TEXT,
  guard TEXT, chars INTEGER, text TEXT -- exactly what was sent (already redacted), capped
);
CREATE INDEX IF NOT EXISTS egress_ts ON egress(ts);
CREATE TABLE IF NOT EXISTS ws_events (
  id INTEGER PRIMARY KEY AUTOINCREMENT, session_id TEXT, ts INTEGER, event TEXT
);
CREATE INDEX IF NOT EXISTS ws_events_session ON ws_events(session_id, id);
CREATE TABLE IF NOT EXISTS tasks (
  id TEXT PRIMARY KEY, root TEXT, worktree TEXT, branch TEXT, base TEXT, session_id TEXT, title TEXT, model TEXT,
  status TEXT, note TEXT, created INTEGER, updated INTEGER
);
CREATE TABLE IF NOT EXISTS browser_sessions (hash TEXT PRIMARY KEY, created INTEGER); -- sha256 of a browser's session id
CREATE TABLE IF NOT EXISTS arena (id TEXT PRIMARY KEY, ts INTEGER, class TEXT, run_a TEXT, run_b TEXT, text_b TEXT, winner TEXT);
`;

export function openDb(home: string): Database {
  const file = join(home, "hib.db");
  const fresh = !existsSync(file);
  const db = new Database(file, { create: true });
  if (fresh) chmodSync(file, 0o600);
  db.exec("PRAGMA journal_mode = WAL;");
  db.exec(SCHEMA);
  migrate(db);
  return db;
}

// Columns added after the first release; ALTER fails harmlessly when they already exist.
function migrate(db: Database) {
  for (const col of ["workspace TEXT", "native_id TEXT", "agent_model TEXT"]) {
    try {
      db.exec(`ALTER TABLE conversations ADD COLUMN ${col}`);
    } catch {}
  }
  try {
    db.exec("ALTER TABLE workspaces ADD COLUMN policy TEXT");
  } catch {}
}

export function memoryDb(): Database {
  const db = new Database(":memory:");
  db.exec(SCHEMA);
  migrate(db);
  return db;
}
