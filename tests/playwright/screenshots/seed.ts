/**
 * Seed a running persea instance with deterministic data for the canonical
 * screenshot set (wayfinder/v1.2.0/S18).
 *
 * Everything here is reproducible: fixed names, fixed timestamps, fixed file
 * sizes and mtimes. Run it against a FRESH instance (or re-run it — it is
 * idempotent) before running tests/playwright/screenshots/screenshots.spec.ts.
 *
 * Requirements:
 *   - persea running (see .github/workflows/screenshots.yml for the CI flow)
 *   - ADMIN_API_KEY (created with `persea --config <cfg> add-admin`)
 *   - SHOT_DB: path to the SQLite admin DB (seeded via the sqlite3 CLI)
 *   - SHOT_RECORDING_DIR: the config's recording path
 *   - SHOT_SSH_KEY: optional path to the SSH private key used by the demo
 *     sshd (only needed for the live-session shot; see screenshots.spec.ts)
 *
 * Environment:
 *   BASE_URL  default http://localhost:8089
 */
import { createHash } from 'crypto';
import { execFileSync } from 'child_process';
import { mkdirSync, writeFileSync, rmSync, readFileSync, existsSync } from 'fs';
import { join } from 'path';

const BASE_URL = process.env.BASE_URL || 'http://localhost:8089';
const ADMIN_KEY = process.env.ADMIN_API_KEY || '';
const SHOT_DB = process.env.SHOT_DB || '';
const SHOT_RECORDING_DIR = process.env.SHOT_RECORDING_DIR || '';
const SHOT_SSH_KEY = process.env.SHOT_SSH_KEY || '';

if (!ADMIN_KEY || !SHOT_DB || !SHOT_RECORDING_DIR) {
  console.error(
    'seed.ts requires ADMIN_API_KEY, SHOT_DB and SHOT_RECORDING_DIR env vars',
  );
  process.exit(1);
}

let CSRF = '';
async function csrfInit() {
  const res = await fetch(`${BASE_URL}/`, { headers: { Authorization: `Bearer ${ADMIN_KEY}` } });
  const setCookie = res.headers.get('set-cookie') || '';
  const m = setCookie.match(/csrf_token=([a-f0-9]+)/);
  if (!m) throw new Error('no csrf_token cookie in response');
  CSRF = m[1];
}

async function api(method: string, path: string, body?: unknown, expectStatus?: number) {
  const res = await fetch(`${BASE_URL}${path}`, {
    method,
    headers: {
      Authorization: `Bearer ${ADMIN_KEY}`,
      'X-CSRF-Token': CSRF,
      Cookie: `csrf_token=${CSRF}`,
      ...(body !== undefined ? { 'Content-Type': 'application/json' } : {}),
    },
    body: body !== undefined ? JSON.stringify(body) : undefined,
  });
  if (expectStatus !== undefined && res.status !== expectStatus) {
    const text = await res.text();
    throw new Error(`${method} ${path} -> HTTP ${res.status} (wanted ${expectStatus}): ${text.slice(0, 300)}`);
  }
  return res;
}

// ── Address book ────────────────────────────────────────────────────────────

const FOLDERS: Array<{ name: string; description: string }> = [
  { name: 'Production', description: 'Live infrastructure — shared services' },
  { name: 'Staging', description: 'Pre-production test environment' },
];

const ENTRIES: Record<string, Array<Record<string, unknown>>> = {
  Production: [
    {
      name: 'Web Server — SSH',
      type: 'ssh',
      hostname: 'web01.prod.example.com',
      port: 22,
      username: 'deploy',
      display_name: 'Web Server',
      description: 'Primary NGINX frontend — SSH console access',
    },
    {
      name: 'Database Host — SSH',
      type: 'ssh',
      hostname: 'db01.prod.example.com',
      port: 22,
      username: 'dba',
      display_name: 'Database Host',
      description: 'PostgreSQL 16 primary',
    },
    {
      name: 'Windows VM — RDP',
      type: 'rdp',
      hostname: 'win10-prod.example.com',
      port: 3389,
      username: 'admin',
      display_name: 'Windows VM',
      description: 'Windows Server 2022 — RemoteApp enabled',
    },
    {
      name: 'Kiosk Display — VNC',
      type: 'vnc',
      hostname: 'kiosk-lobby.example.com',
      port: 5900,
      username: '',
      display_name: 'Kiosk Display',
      description: 'Lobby display kiosk',
    },
  ],
  Staging: [
    {
      name: 'Test Node — SSH',
      type: 'ssh',
      hostname: 'test01.staging.example.com',
      port: 22,
      username: 'tester',
      display_name: 'Test Node',
      description: 'Staging application server',
    },
  ],
};

async function seedAddressBook() {
  for (const folder of FOLDERS) {
    await api('DELETE', `/api/addressbook/folders/shared/${encodeURIComponent(folder.name)}`);
    await api('POST', '/api/addressbook/folders', {
      name: folder.name,
      description: folder.description,
      scope: 'shared',
      inherit_from_parent: false,
      allowed_groups: [],
    }, 201);
    for (const entry of ENTRIES[folder.name]) {
      await api(
        'POST',
        `/api/addressbook/folders/shared/${encodeURIComponent(folder.name)}/entries`,
        { name: entry.name, ...entry },
        201,
      );
    }
  }
  console.log('address book seeded');
}

// ── SQLite rows (session history, audit chain, user tokens) ─────────────────

const sha256 = (s: string) => createHash('sha256').update(s).digest('hex');

interface AuditSeed {
  event_type: string;
  timestamp: string; // RFC3339 with +00:00, as chrono renders it
  user_id: string;
  source_ip: string;
  outcome: string;
  details: Record<string, unknown>;
  session_id: string | null;
}

// Replicate src/audit.rs::compute_event_hash: SHA-256 over canonical JSON
// (alphabetically sorted keys at every level, no whitespace) of the event
// fields, so the seeded chain passes the "Verify chain" button too. Fields
// that are NULL in the DB are omitted from the JSON entirely (the Rust side
// only inserts Some(...) fields); serde_json's Map sorts keys (BTreeMap), so
// nested objects are serialized with sorted keys as well.
function canonicalJson(value: unknown): string {
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(',')}]`;
  if (value !== null && typeof value === 'object') {
    const obj = value as Record<string, unknown>;
    const parts = Object.keys(obj)
      .sort()
      .map((k) => `${JSON.stringify(k)}:${canonicalJson(obj[k])}`);
    return `{${parts.join(',')}}`;
  }
  return JSON.stringify(value);
}

function auditHash(e: AuditSeed): string {
  const fields: Record<string, unknown> = {
    details: e.details,
    event_type: e.event_type,
    outcome: e.outcome,
    source_ip: e.source_ip,
    timestamp: e.timestamp,
    user_id: e.user_id,
  };
  if (e.session_id !== null) fields.session_id = e.session_id;
  return sha256(canonicalJson(fields));
}

const SESSION_IDS = {
  webServer: '6f0a1b2c-9c41-4a6e-b2f1-001122334455',
  windowsVm: '7f1a2b3c-8d52-4b7f-c3f2-002233445566',
  databaseHost: '8f2a3b4c-7d63-4c80-d4f3-003344556677',
  kiosk: '9f3a4b5c-6e74-4d91-e5f4-004455667788',
};

const AUDIT_EVENTS: AuditSeed[] = [
  {
    event_type: 'auth.login.success',
    timestamp: '2026-08-11T08:00:00+00:00',
    user_id: 'admin@local.test',
    source_ip: '192.0.2.10',
    outcome: 'success',
    details: { method: 'password' },
    session_id: null,
  },
  {
    event_type: 'session.start',
    timestamp: '2026-08-11T09:12:00+00:00',
    user_id: 'admin@local.test',
    source_ip: '192.0.2.10',
    outcome: 'success',
    details: { session_type: 'ssh', target: 'web01.prod.example.com:22' },
    session_id: SESSION_IDS.webServer,
  },
  {
    event_type: 'session.end',
    timestamp: '2026-08-11T09:47:00+00:00',
    user_id: 'admin@local.test',
    source_ip: '192.0.2.10',
    outcome: 'success',
    details: { duration_secs: 2100 },
    session_id: SESSION_IDS.webServer,
  },
  {
    event_type: 'auth.login.failure',
    timestamp: '2026-08-11T10:20:00+00:00',
    user_id: 'bob@example.com',
    source_ip: '203.0.113.77',
    outcome: 'failure',
    details: { method: 'password', reason: 'invalid credentials' },
    session_id: null,
  },
  {
    event_type: 'admin.role.change',
    timestamp: '2026-08-12T06:45:00+00:00',
    user_id: 'admin@local.test',
    source_ip: '192.0.2.10',
    outcome: 'success',
    details: { user: 'carol@example.com', from: 'viewer', to: 'operator' },
    session_id: null,
  },
  {
    event_type: 'user.password.change',
    timestamp: '2026-08-12T07:10:00+00:00',
    user_id: 'admin@local.test',
    source_ip: '192.0.2.10',
    outcome: 'success',
    details: { user: 'admin@local.test' },
    session_id: null,
  },
  {
    event_type: 'session.start',
    timestamp: '2026-08-12T14:03:00+00:00',
    user_id: 'admin@local.test',
    source_ip: '192.0.2.10',
    outcome: 'success',
    details: { session_type: 'rdp', target: 'win10-prod.example.com:3389' },
    session_id: SESSION_IDS.windowsVm,
  },
];

// The admin user created by the setup wizard carries the display name
// "Administrator"; session-history rows are attributed to that name.
const SEED_USER = 'Administrator';

function seedSqlite() {
  const rows: Array<Array<string | null>> = [];
  let prevHash = '0'.repeat(64);
  for (const e of AUDIT_EVENTS) {
    const eventHash = auditHash(e);
    rows.push([
      e.event_type,
      e.timestamp,
      e.user_id,
      e.source_ip,
      e.outcome,
      JSON.stringify(e.details),
      e.session_id,
      prevHash,
      eventHash,
    ]);
    prevHash = eventHash;
  }

  const sql = `
BEGIN;
DELETE FROM session_history;
DELETE FROM audit_events;
DELETE FROM user_api_tokens;
DELETE FROM token_audit_log;

-- The address-book rows were created moments ago via the API; pin their
-- timestamps so the connections detail panel (Created/Updated fields) is
-- deterministic across regenerations.
UPDATE address_book_folders
   SET created_at = '2026-08-01 08:00:00', updated_at = '2026-08-05 09:00:00';
UPDATE address_book_entries
   SET created_at = '2026-08-01 08:30:00', updated_at = '2026-08-10 14:00:00';

INSERT INTO session_history
  (session_id, session_type, hostname, port, username, created_by,
   address_book_entry, address_book_folder, entry_display_name,
   started_at, ended_at, duration_secs, status, reason)
VALUES
  ('${SESSION_IDS.webServer}', 'ssh', 'web01.prod.example.com', 22, 'deploy',
   '${SEED_USER}', 'web-server', 'Production', 'Web Server',
   '2026-08-11 09:12:00', '2026-08-11 09:47:00', 2100, 'completed', 'Scheduled maintenance'),
  ('${SESSION_IDS.windowsVm}', 'rdp', 'win10-prod.example.com', 3389, 'admin',
   '${SEED_USER}', 'windows-vm', 'Production', 'Windows VM',
   '2026-08-11 14:03:00', '2026-08-11 14:58:00', 3300, 'completed', 'Configuration change'),
  ('${SESSION_IDS.databaseHost}', 'ssh', 'db01.prod.example.com', 22, 'dba',
   '${SEED_USER}', 'database-host', 'Production', 'Database Host',
   '2026-08-12 07:30:00', '2026-08-12 08:05:00', 2100, 'completed', 'Incident response'),
  ('${SESSION_IDS.kiosk}', 'vnc', 'kiosk-lobby.example.com', 5900, '',
   '${SEED_USER}', 'kiosk-display', 'Production', 'Kiosk Display',
   '2026-08-12 10:45:00', NULL, NULL, 'disconnected', 'Visual check');

INSERT INTO audit_events
  (event_type, timestamp, user_id, source_ip, outcome, details, session_id, prev_hash, event_hash)
VALUES
${rows.map((r) => `('${r[0]}', '${r[1]}', '${r[2]}', '${r[3]}', '${r[4]}', '${r[5]}', ${r[6] === null ? 'NULL' : `'${r[6]}'`}, '${r[7]}', '${r[8]}')`).join(',\n')};

INSERT INTO user_api_tokens
  (user_id, name, token_hash, max_role, expires_at, disabled, created_at, last_used_at)
VALUES
  (1, 'ci-deploy', '${'a'.repeat(64)}', 'admin', NULL, 0, '2026-08-01 08:00:00', '2026-08-12 09:15:00'),
  (1, 'backup-script', '${'b'.repeat(64)}', 'operator', '2027-01-31 23:59:59', 0, '2026-07-15 12:30:00', '2026-08-10 22:05:00'),
  (1, 'grafana-dashboard', '${'c'.repeat(64)}', 'viewer', '2026-06-30 23:59:59', 0, '2026-06-01 10:00:00', NULL);

COMMIT;
`;
  execFileSync('sqlite3', [SHOT_DB, sql], { stdio: 'inherit' });
  console.log('sqlite rows seeded (history, audit, tokens)');
}

// ── Recording files ─────────────────────────────────────────────────────────

// Committed fixtures (screenshots/fixtures/) are copied into the recording
// dir: demo-ssh-shell.guac is a REAL guacd capture of a live SSH session
// (terminal prompt rendered by guacd, sync timestamps normalized to fixed 1s
// steps), demo-rdp-desktop.guac is a minimal valid protocol stream. Both are
// plaintext Guacamole recordings the SessionRecording player can replay;
// fixed content + fixed mtimes keep the list view and player frame
// deterministic.
const FIXTURE_DIR = join(__dirname, 'fixtures');

const RECORDINGS: Array<{
  file: string;
  fixture: string;
  meta: Record<string, string>;
  mtime: string;
}> = [
  {
    file: 'demo-ssh-shell.guac',
    fixture: 'demo-ssh-shell.guac',
    meta: {
      created_at: '2026-08-11T09:47:00+00:00',
      user: 'admin@local.test',
      folder: 'Production',
      entry_display_name: 'Web Server',
      session_type: 'ssh',
    },
    mtime: '2026-08-11 09:50:00 UTC',
  },
  {
    file: 'demo-rdp-desktop.guac',
    fixture: 'demo-rdp-desktop.guac',
    meta: {
      created_at: '2026-08-11T14:58:00+00:00',
      user: 'admin@local.test',
      folder: 'Production',
      entry_display_name: 'Windows VM',
      session_type: 'rdp',
    },
    mtime: '2026-08-11 15:04:00 UTC',
  },
];

function seedRecordings() {
  // Wipe the recording dir first: real sessions write .guac files here and
  // would otherwise pollute the deterministic list view.
  rmSync(SHOT_RECORDING_DIR, { recursive: true, force: true });
  mkdirSync(SHOT_RECORDING_DIR, { recursive: true });
  for (const rec of RECORDINGS) {
    const guacPath = join(SHOT_RECORDING_DIR, rec.file);
    const metaPath = join(SHOT_RECORDING_DIR, rec.file.replace(/\.guac$/, '.meta'));
    writeFileSync(guacPath, readFileSync(join(FIXTURE_DIR, rec.fixture)));
    writeFileSync(metaPath, JSON.stringify(rec.meta));
    execFileSync('touch', ['-d', rec.mtime, guacPath]);
    execFileSync('touch', ['-d', rec.mtime, metaPath]);
  }
  console.log('recordings seeded:', SHOT_RECORDING_DIR);
}

async function main() {
  await csrfInit();
  await seedAddressBook();
  seedSqlite();
  seedRecordings();
  if (SHOT_SSH_KEY && existsSync(SHOT_SSH_KEY)) {
    console.log('SSH demo key available at', SHOT_SSH_KEY);
  } else {
    console.log('SHOT_SSH_KEY not set — the live SSH shot will be skipped with a note');
  }
  console.log('seed complete');
}

main().catch((e) => {
  console.error('seed failed:', e.message);
  process.exit(1);
});
