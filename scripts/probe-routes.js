// Probes for devices, grants and refresh, over HTTP on a throwaway database, plus one
// in-process check that counts queries on GET /devices.
//
//   node scripts/probe-routes.js

import { spawn, execFileSync } from 'node:child_process';
import { rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { openDatabase } from '../server/db.js';
import { createRouter } from '../server/router.js';
import { registerRoutes } from '../server/routes/index.js';
import { authenticate } from '../server/context.js';
import { issueAccessToken } from '../server/auth.js';

const PORT = 8125;
const SECRET = 'probe-secret';
const BASE = `http://localhost:${PORT}/v1`;
const DB = join(tmpdir(), `probe-routes-${process.pid}.db`);

execFileSync(process.execPath, ['scripts/load-db.js'], { env: { ...process.env, DATABASE_FILE: DB }, stdio: 'ignore' });
const server = spawn(process.execPath, ['server/index.js'], {
  env: { ...process.env, DATABASE_FILE: DB, PORT: String(PORT), NODE_ENV: 'production', JWT_SECRET: SECRET },
  stdio: ['ignore', 'ignore', 'inherit'],
});
await new Promise((r) => setTimeout(r, 1200));
const db = openDatabase(DB); // a second connection, for setup and for looking at results

let pass = 0, fail = 0;
const check = (label, got, want) => {
  const ok = JSON.stringify(got) === JSON.stringify(want);
  ok ? pass++ : fail++;
  console.log(`${ok ? ' ok  ' : ' FAIL'}  ${label.padEnd(56)} ${ok ? '' : `got ${JSON.stringify(got)} want ${JSON.stringify(want)}`}`);
};

async function call(method, path, { token, body, cookie } = {}) {
  const headers = {};
  if (token) headers.authorization = `Bearer ${token}`;
  if (body) headers['content-type'] = 'application/json';
  if (cookie) headers.cookie = cookie;
  const res = await fetch(BASE + path, { method, headers, body: body ? JSON.stringify(body) : undefined });
  const text = await res.text();
  return { status: res.status, body: text ? JSON.parse(text) : null, setCookie: res.headers.get('set-cookie') };
}
const login = async (email, password = 'demo1234') =>
  call('POST', '/auth/login', { body: { email, password } });
const tokenOf = async (email) => (await login(email)).body.token;
const err = (r) => [r.status, r.body?.error?.code, r.body?.error?.reason];
const cookieOf = (r) => r.setCookie?.split(';')[0];

try {
  const dana = await tokenOf('dana@example.test');      // owner, Acme
  const viewer = await tokenOf('viewer@acme.test');     // viewer, Acme
  const admin = await tokenOf('admin@acme.test');       // admin, Acme
  const sam = await tokenOf('sam@example.test');        // operator, Acme

  console.log('\n== device:view deny hides the row ==');
  const vList = await call('GET', '/orgs/org_acme/devices', { token: viewer });
  check('kiosk-lobby-01 not in the viewer\'s list', vList.body.devices.some((d) => d.id === 'dev_kiosk_lobby_01'), false);
  const hidden = await call('GET', '/orgs/org_acme/devices/dev_kiosk_lobby_01', { token: viewer });
  const nothing = await call('GET', '/orgs/org_acme/devices/dev_does_not_exist', { token: viewer });
  check('GET on it is 404', hidden.status, 404);
  check('  ...same body as a device that does not exist',
    [hidden.body.error.code, hidden.body.error.message], [nothing.body.error.code, nothing.body.error.message]);
  check('  ...and the attempt is audited as a deny',
    db.prepare("SELECT result, reason_code FROM audit_events WHERE target_id = 'dev_kiosk_lobby_01' AND action = 'device.view'").get(),
    { result: 'deny', reason_code: 'not_visible' });
  check('owner does see it', (await call('GET', '/orgs/org_acme/devices/dev_kiosk_lobby_01', { token: dana })).status, 200);

  console.log('\n== devices: write paths ==');
  const made = await call('POST', '/orgs/org_acme/devices', { token: dana, body: { name: 'probe-box', kind: 'linux' } });
  check('provision -> 201 with its permissions', [made.status, made.body.permissions?.['device:control']?.effect], [201, 'allow']);
  check('bad kind -> 400', (await call('POST', '/orgs/org_acme/devices', { token: dana, body: { name: 'x', kind: 'toaster' } })).status, 400);
  check('viewer cannot provision -> 403', err(await call('POST', '/orgs/org_acme/devices', { token: viewer, body: { name: 'x', kind: 'linux' } })), [403, 'FORBIDDEN', 'missing_permission']);
  check('rename -> 200', (await call('PATCH', `/orgs/org_acme/devices/${made.body.id}`, { token: dana, body: { name: 'probe-box-2' } })).body.name, 'probe-box-2');
  check('decommission -> 204', (await call('DELETE', `/orgs/org_acme/devices/${made.body.id}`, { token: dana })).status, 204);
  check('  ...then GET -> 404', (await call('GET', `/orgs/org_acme/devices/${made.body.id}`, { token: dana })).status, 404);

  console.log('\n== transfer ==');
  const t = await call('POST', '/orgs/org_acme/devices', { token: dana, body: { name: 'probe-move', kind: 'linux' } });
  db.prepare(`INSERT INTO grants (id, org_id, user_id, device_id, effect, created_by) VALUES ('grt_probe_mv', 'org_acme', 'usr_acme_viewer', ?, 'allow', 'usr_dana')`).run(t.body.id);
  db.prepare(`INSERT INTO grant_permissions VALUES ('grt_probe_mv', 'device:control')`).run();
  const ownerAcme = await tokenOf('owner@acme.test');
  check('target org you are not in -> 404', (await call('POST', `/orgs/org_acme/devices/${t.body.id}/transfer`, { token: ownerAcme, body: { targetOrgId: 'org_globex' } })).status, 404);
  check('dana is only viewer in Globex -> 403', err(await call('POST', `/orgs/org_acme/devices/${t.body.id}/transfer`, { token: dana, body: { targetOrgId: 'org_globex' } }))[0], 403);
  db.prepare("UPDATE memberships SET role = 'owner' WHERE user_id = 'usr_dana' AND org_id = 'org_globex'").run();
  const moved = await call('POST', `/orgs/org_acme/devices/${t.body.id}/transfer`, { token: dana, body: { targetOrgId: 'org_globex' } });
  check('owner in both -> 200', moved.status, 200);
  check('  ...gone from Acme', (await call('GET', `/orgs/org_acme/devices/${t.body.id}`, { token: dana })).status, 404);
  check('  ...its Acme grant is revoked', db.prepare("SELECT revoked_at IS NOT NULL AS r FROM grants WHERE id = 'grt_probe_mv'").get().r, 1);

  console.log('\n== grants: validation, in AUTH-DATA-MODEL §8 order ==');
  const g = (token, body) => call('POST', '/orgs/org_acme/grants', { token, body });
  check('device:teleport -> 400 unknown_permission', err(await g(dana, { userId: 'usr_acme_viewer', effect: 'allow', permissions: ['device:teleport'] })), [400, 'VALIDATION', 'unknown_permission']);
  check('  ...and nothing was half-written', db.prepare("SELECT count(*) n FROM grants g LEFT JOIN grant_permissions gp ON gp.grant_id = g.id WHERE gp.grant_id IS NULL").get().n, 0);
  check('empty permissions -> 400', (await g(dana, { userId: 'usr_acme_viewer', effect: 'allow', permissions: [] })).status, 400);
  check('effect "maybe" -> 400', (await g(dana, { userId: 'usr_acme_viewer', effect: 'maybe', permissions: ['audit:read'] })).status, 400);
  check('device in another org -> 404', (await g(dana, { userId: 'usr_acme_viewer', deviceId: 'dev_globex_desk_01', effect: 'allow', permissions: ['device:control'] })).status, 404);
  check('target not a member -> 404', (await g(dana, { userId: 'usr_globex_owner', effect: 'allow', permissions: ['audit:read'] })).status, 404);
  check('expiresAt in the past -> 400 GRANT_EXPIRED', err(await g(dana, { userId: 'usr_acme_viewer', effect: 'allow', permissions: ['audit:read'], expiresAt: '2020-01-01T00:00:00Z' })).slice(0, 2), [400, 'GRANT_EXPIRED']);
  check('bad timestamp -> 400', (await g(dana, { userId: 'usr_acme_viewer', effect: 'allow', permissions: ['audit:read'], expiresAt: 'soon' })).status, 400);

  console.log('\n== grants: self-grant and laundering ==');
  check('self-grant -> 403', err(await g(dana, { userId: 'usr_dana', effect: 'allow', permissions: ['audit:read'] })), [403, 'FORBIDDEN', 'self_grant']);
  check('  ...audited as a deny', db.prepare("SELECT count(*) n FROM audit_events WHERE action = 'grant.create' AND result = 'deny' AND reason_code = 'self_grant'").get().n, 1);
  check('admin grants org:delete (admin lacks it) -> 403', err(await g(admin, { userId: 'usr_acme_viewer', effect: 'allow', permissions: ['org:delete'] }))[0], 403);
  check('admin grants "*" -> 403 (covers org:delete)', err(await g(admin, { userId: 'usr_acme_viewer', effect: 'allow', permissions: ['*'] }))[0], 403);
  check('operator has no grant:create -> 403', err(await g(sam, { userId: 'usr_acme_viewer', effect: 'allow', permissions: ['device:view'] }))[0], 403);

  console.log('\n== grants: create, list, revoke ==');
  const viewerBefore = await tokenOf('viewer@acme.test');
  const made2 = await g(dana, { userId: 'usr_acme_viewer', effect: 'allow', permissions: ['audit:read', 'audit:read'] });
  check('create -> 201, duplicates collapsed', [made2.status, made2.body.permissions], [201, ['audit:read']]);
  check('  ...target\'s old token is now stale', (await call('GET', '/auth/me', { token: viewerBefore })).body.error.code, 'TOKEN_STALE');
  const viewerAfter = await tokenOf('viewer@acme.test');
  check('  ...new token has audit:read', (await call('GET', '/auth/me', { token: viewerAfter })).body.permissions['audit:read'].effect, 'allow');
  check('list needs user:read (operator) -> 403', (await call('GET', '/orgs/org_acme/grants', { token: sam })).status, 403);
  check('list ?userId filters', (await call('GET', '/orgs/org_acme/grants?userId=usr_acme_viewer', { token: dana })).body.grants.every((x) => x.userId === 'usr_acme_viewer'), true);
  check('revoke -> 204', (await call('DELETE', `/orgs/org_acme/grants/${made2.body.id}`, { token: dana })).status, 204);
  check('revoke again -> 404', (await call('DELETE', `/orgs/org_acme/grants/${made2.body.id}`, { token: dana })).status, 404);
  db.prepare(`INSERT INTO grants (id, org_id, user_id, effect, created_by) VALUES ('grt_probe_self', 'org_acme', 'usr_dana', 'deny', 'usr_acme_owner')`).run();
  db.prepare(`INSERT INTO grant_permissions VALUES ('grt_probe_self', 'device:terminal')`).run();
  check('revoking a deny on yourself -> 403', err(await call('DELETE', '/orgs/org_acme/grants/grt_probe_self', { token: await tokenOf('dana@example.test') })), [403, 'FORBIDDEN', 'self_grant']);

  console.log('\n== refresh: rotation and replay ==');
  const first = await login('admin@acme.test');
  const a = cookieOf(first);
  const r1 = await call('POST', '/auth/refresh', { cookie: a });
  const b = cookieOf(r1);
  check('refresh with A -> 200, new cookie B', [r1.status, !!b && b !== a], [200, true]);
  check('  ...B is a fresh access token', (await call('GET', '/auth/me', { token: r1.body.token })).status, 200);
  check('replay A -> 401', (await call('POST', '/auth/refresh', { cookie: a })).status, 401);
  check('  ...and B is dead too (family revoked)', (await call('POST', '/auth/refresh', { cookie: b })).status, 401);
  check('another login (new family) still works', (await call('POST', '/auth/refresh', { cookie: cookieOf(await login('admin@acme.test')) })).status, 200);
  check('no cookie -> 401', (await call('POST', '/auth/refresh')).status, 401);
  check('access token as the cookie -> 401', (await call('POST', '/auth/refresh', { cookie: `refresh_token=${first.body.token}` })).status, 401);

  console.log('\n== a reinstated user\'s old token ==');
  const samOld = await tokenOf('sam@example.test');
  // No members routes yet: do what suspend + reinstate will do, directly.
  db.prepare("UPDATE memberships SET status = 'suspended', perm_version = perm_version + 1 WHERE user_id = 'usr_sam' AND org_id = 'org_acme'").run();
  check('while suspended: 403 suspended', err(await call('GET', '/orgs/org_acme/devices', { token: samOld })), [403, 'FORBIDDEN', 'suspended']);
  db.prepare("UPDATE memberships SET status = 'active', perm_version = perm_version + 1 WHERE user_id = 'usr_sam' AND org_id = 'org_acme'").run();
  check('after reinstate: old token -> 401 TOKEN_STALE', err(await call('GET', '/orgs/org_acme/devices', { token: samOld })).slice(0, 2), [401, 'TOKEN_STALE']);
  check('  ...a new login works', (await call('GET', '/orgs/org_acme/devices', { token: await tokenOf('sam@example.test') })).status, 200);

  console.log('\n== GET /devices: query count stays flat as devices grow ==');
  const counts = [];
  for (const add of [0, 100]) {
    for (let i = 0; i < add; i++) {
      db.prepare("INSERT INTO devices (id, org_id, name, kind) VALUES (?, 'org_acme', ?, 'linux')").run(`dev_probe_${i}`, `probe-${i}`);
    }
    counts.push(countListQueries());
  }
  console.log(`        queries: ${counts[0].queries} with ${counts[0].rows} rows, ${counts[1].queries} with ${counts[1].rows} rows`);
  check('same number of queries', counts[0].queries === counts[1].queries, true);
} finally {
  server.kill();
  db.close();
  await new Promise((r) => setTimeout(r, 300));
  for (const s of ['', '-wal', '-shm']) rmSync(DB + s, { force: true });
}

// In-process: the real router, context and handler, on a connection whose statements
// count their own executions. Mirrors the private-route path in server/index.js.
function countListQueries() {
  let queries = 0;
  const raw = openDatabase(DB);
  const counting = new Proxy(raw, {
    get(target, key) {
      if (key === 'prepare') {
        return (sql) => new Proxy(target.prepare(sql), {
          get(stmt, m) {
            const v = stmt[m];
            if (['run', 'get', 'all', 'iterate'].includes(m)) return (...args) => { queries++; return v.apply(stmt, args); };
            return typeof v === 'function' ? v.bind(stmt) : v;
          },
        });
      }
      const v = target[key];
      return typeof v === 'function' ? v.bind(target) : v;
    },
  });
  const router = createRouter();
  registerRoutes(router, { db: counting, secret: SECRET });
  const m = raw.prepare("SELECT role, perm_version FROM memberships WHERE user_id = 'usr_acme_viewer' AND org_id = 'org_acme'").get();
  const token = issueAccessToken({ userId: 'usr_acme_viewer', orgId: 'org_acme', role: m.role, permVersion: m.perm_version }, SECRET);

  const hit = router.match('GET', '/v1/orgs/org_acme/devices');
  let body;
  const res = { writeHead() {}, end(p) { body = JSON.parse(p); } };
  queries = 0;
  const ctx = { db: counting, secret: SECRET, requestId: 'req_probe', query: new URLSearchParams(), body: {} };
  Object.assign(ctx, authenticate(counting, SECRET)({ headers: { authorization: `Bearer ${token}` } }, hit.params));
  hit.handler(ctx, hit.params, res);
  const result = { queries, rows: body.devices.length };
  raw.close();
  return result;
}

console.log(`\n${fail === 0 ? 'ALL PASS' : 'FAILURES'} — ${pass} passed, ${fail} failed\n`);
process.exit(fail === 0 ? 0 : 1);
