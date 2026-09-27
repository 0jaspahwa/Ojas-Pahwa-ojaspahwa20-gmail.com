// Probes for sessions and the audit list. Two server processes share one throwaway
// database, so "parallel" requests really do race: inside one process the handlers are
// synchronous and can never interleave.
//
//   node scripts/probe-sessions.js

import { spawn, execFileSync } from 'node:child_process';
import { rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { openDatabase } from '../server/db.js';

const SECRET = 'probe-secret';
const PORTS = [8126, 8127];
const DB = join(tmpdir(), `probe-sessions-${process.pid}.db`);

execFileSync(process.execPath, ['scripts/load-db.js'], { env: { ...process.env, DATABASE_FILE: DB }, stdio: 'ignore' });
const servers = PORTS.map((port) => spawn(process.execPath, ['server/index.js'], {
  env: { ...process.env, DATABASE_FILE: DB, PORT: String(port), NODE_ENV: 'production', JWT_SECRET: SECRET },
  stdio: ['ignore', 'ignore', 'inherit'],
}));
await new Promise((r) => setTimeout(r, 1500));
const db = openDatabase(DB);

let pass = 0, fail = 0;
const check = (label, got, want) => {
  const ok = JSON.stringify(got) === JSON.stringify(want);
  ok ? pass++ : fail++;
  console.log(`${ok ? ' ok  ' : ' FAIL'}  ${label.padEnd(56)} ${ok ? '' : `got ${JSON.stringify(got)} want ${JSON.stringify(want)}`}`);
};

async function call(method, path, { token, body, port = PORTS[0] } = {}) {
  const headers = {};
  if (token) headers.authorization = `Bearer ${token}`;
  if (body) headers['content-type'] = 'application/json';
  const res = await fetch(`http://localhost:${port}/v1${path}`, { method, headers, body: body ? JSON.stringify(body) : undefined });
  const text = await res.text();
  return { status: res.status, body: text ? JSON.parse(text) : null };
}
const tokenOf = async (email) =>
  (await call('POST', '/auth/login', { body: { email, password: 'demo1234' } })).body.token;
const start = (token, deviceId, mode, port) => call('POST', '/orgs/org_acme/sessions', { token, body: { deviceId, mode }, port });

try {
  const dana = await tokenOf('dana@example.test');   // owner
  const sam = await tokenOf('sam@example.test');     // operator
  const admin = await tokenOf('admin@acme.test');

  console.log('\n== parallel control requests: exactly one wins ==');
  let rounds = 0;
  for (let i = 0; i < 10; i++) {
    const dev = (await call('POST', '/orgs/org_acme/devices', { token: dana, body: { name: `race-${i}`, kind: 'linux' } })).body.id;
    // Same instant, two processes, two different users. (Not terminal for Sam: the seed
    // denies him device:terminal org-wide, so he would get 403 before any race.)
    const [a, b] = await Promise.all([start(dana, dev, 'control', PORTS[0]), start(sam, dev, 'control', PORTS[1])]);
    const statuses = [a.status, b.status].sort();
    const active = db.prepare("SELECT count(*) n FROM sessions WHERE device_id = ? AND state = 'active'").get(dev).n;
    if (JSON.stringify(statuses) === '[201,409]' && active === 1) rounds++;
    else console.log(`        round ${i}: statuses ${statuses}, active rows ${active}`);
  }
  check('10 rounds: one 201 and one 409, one active row each', rounds, 10);
  const busy = await start(sam, 'dev_lab_win_01', 'control');
  const holder = await start(dana, 'dev_lab_win_01', 'control');
  check('409 names the holder\'s session', holder.body.error.message.includes(busy.body.id), true);
  check('  ...code DEVICE_BUSY', holder.body.error.code, 'DEVICE_BUSY');

  console.log('\n== view is not exclusive ==');
  const views = await Promise.all([start(dana, 'dev_lab_win_01', 'view', PORTS[0]), start(sam, 'dev_lab_win_01', 'view', PORTS[1]), start(admin, 'dev_lab_win_01', 'view', PORTS[0])]);
  check('3 parallel views while control is held: all 201', views.map((v) => v.status), [201, 201, 201]);

  console.log('\n== input, and 404 before 403 ==');
  const viewer = await tokenOf('viewer@acme.test');
  check('mode "admin" -> 400, before any permission check', (await start(viewer, 'dev_lab_mac_01', 'admin')).status, 400);
  check('device in another org -> 404', (await start(dana, 'dev_globex_desk_01', 'view')).status, 404);
  check('denied start is audited with its reason',
    (await start(viewer, 'dev_qa_android_01', 'view')).status === 403 &&
    db.prepare("SELECT reason_code FROM audit_events WHERE action = 'session.start' AND result = 'deny' AND target_id = 'dev_qa_android_01'").get()?.reason_code,
    'missing_permission');

  console.log('\n== grandfathering: revoke leaves the running session alone ==');
  const running = await start(viewer, 'dev_lab_mac_01', 'view');
  check('viewer starts a view session (via grant)', running.status, 201);
  check('  ...snapshot records the grant it ran on',
    JSON.parse(db.prepare('SELECT authorized_by FROM sessions WHERE id = ?').get(running.body.id).authorized_by)['session:start'].source,
    'grant:grt_viewer_start_session');
  check('owner revokes that grant', (await call('DELETE', '/orgs/org_acme/grants/grt_viewer_start_session', { token: dana })).status, 204);
  check('  ...running session is still active', (await call('GET', `/sessions/${running.body.id}`, { token: dana })).body.state, 'active');
  check('  ...old token cannot start another (stale)', (await start(viewer, 'dev_lab_mac_01', 'view')).status, 401);
  check('  ...new token cannot either (403)', (await start(await tokenOf('viewer@acme.test'), 'dev_lab_mac_01', 'view')).status, 403);

  console.log('\n== expiry ==');
  // A new device: the seed already holds an active control session on build-server-01.
  const exp = (await call('POST', '/orgs/org_acme/devices', { token: dana, body: { name: 'expiry-box', kind: 'linux' } })).body.id;
  db.prepare(`INSERT INTO sessions (id, org_id, user_id, device_id, mode, state, authorized_by, started_at, expires_at)
              VALUES ('ses_probe_old', 'org_acme', 'usr_dana', ?, 'control', 'active', '{}',
                      '2020-01-01T00:00:00.000Z', '2020-01-01T01:00:00.000Z')`).run(exp);
  const old = (await call('GET', '/sessions/ses_probe_old', { token: dana })).body;
  check('expired session reads as ended', [old.state, old.end_reason], ['ended', 'session_expired']);
  check('  ...ended_at is its expiry, not "now"', old.ended_at, '2020-01-01T01:00:00.000Z');
  db.prepare(`INSERT INTO sessions (id, org_id, user_id, device_id, mode, state, authorized_by, started_at, expires_at)
              VALUES ('ses_probe_old2', 'org_acme', 'usr_dana', ?, 'control', 'active', '{}',
                      '2020-01-01T00:00:00.000Z', '2020-01-01T01:00:00.000Z')`).run(exp);
  check('an expired control does not block a new one', (await start(sam, exp, 'control')).status, 201);
  const fresh = db.prepare("SELECT started_at, expires_at FROM sessions WHERE device_id = ? AND state = 'active'").get(exp);
  check('new session expires after max_session_minutes (60)', (Date.parse(fresh.expires_at) - Date.parse(fresh.started_at)) / 60000, 60);

  console.log('\n== read and end ==');
  const mine = (await start(dana, 'dev_lab_mac_01', 'view')).body.id;
  check('another org\'s token -> 404', (await call('GET', `/sessions/${mine}`, { token: await tokenOf('owner@globex.test') })).status, 404);
  check('operator (session:view) reads it', (await call('GET', `/sessions/${mine}`, { token: sam })).status, 200);
  check('operator cannot terminate it -> 403', (await call('DELETE', `/sessions/${mine}`, { token: sam })).status, 403);
  check('admin terminates it', (await call('DELETE', `/sessions/${mine}`, { token: admin })).body.end_reason, 'admin_terminated');
  check('  ...again -> 409', (await call('DELETE', `/sessions/${mine}`, { token: admin })).status, 409);
  const own = (await start(sam, 'dev_lab_mac_01', 'view')).body.id;
  check('stopping your own -> user_stopped', (await call('DELETE', `/sessions/${own}`, { token: sam })).body.end_reason, 'user_stopped');

  console.log('\n== audit list ==');
  const page = (q, t = dana) => call('GET', `/orgs/org_acme/audit?${q}`, { token: t });
  const all = (await page('limit=500')).body.events;
  check('newest first', all.every((e, i) => i === 0 || all[i - 1].at >= e.at), true);
  check('only this org', all.every((e) => e.org_id === 'org_acme'), true);
  check('limit=2&offset=1 is a window of the full list', (await page('limit=2&offset=1')).body.events.map((e) => e.id), all.slice(1, 3).map((e) => e.id));
  for (const q of ['limit=1.5', 'limit=abc', 'limit=', 'offset=1e3', 'limit=501']) check(`audit?${q} -> 400`, (await page(q)).status, 400);
} finally {
  for (const s of servers) s.kill();
  db.close();
  await new Promise((r) => setTimeout(r, 300));
  for (const s of ['', '-wal', '-shm']) rmSync(DB + s, { force: true });
}

console.log(`\n${fail === 0 ? 'ALL PASS' : 'FAILURES'} — ${pass} passed, ${fail} failed\n`);
process.exit(fail === 0 ? 0 : 1);
