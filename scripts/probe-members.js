// Probes for orgs, members and invites. Two server processes share one throwaway
// database, so the race checks really race.
//
//   node scripts/probe-members.js

import { spawn, execFileSync } from 'node:child_process';
import { rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { openDatabase } from '../server/db.js';

const PORTS = [8128, 8129];
const DB = join(tmpdir(), `probe-members-${process.pid}.db`);

execFileSync(process.execPath, ['scripts/load-db.js'], { env: { ...process.env, DATABASE_FILE: DB }, stdio: 'ignore' });
const servers = PORTS.map((port) => spawn(process.execPath, ['server/index.js'], {
  env: { ...process.env, DATABASE_FILE: DB, PORT: String(port), NODE_ENV: 'production', JWT_SECRET: 'probe-secret' },
  stdio: ['ignore', 'ignore', 'inherit'],
}));
await new Promise((r) => setTimeout(r, 1500));
const db = openDatabase(DB);

let pass = 0, fail = 0;
const check = (label, got, want) => {
  const ok = JSON.stringify(got) === JSON.stringify(want);
  ok ? pass++ : fail++;
  console.log(`${ok ? ' ok  ' : ' FAIL'}  ${label.padEnd(58)} ${ok ? '' : `got ${JSON.stringify(got)} want ${JSON.stringify(want)}`}`);
};

async function call(method, path, { token, body, port = PORTS[0] } = {}) {
  const headers = {};
  if (token) headers.authorization = `Bearer ${token}`;
  if (body) headers['content-type'] = 'application/json';
  const res = await fetch(`http://localhost:${port}/v1${path}`, { method, headers, body: body ? JSON.stringify(body) : undefined });
  const text = await res.text();
  return { status: res.status, body: text ? JSON.parse(text) : null, cookie: res.headers.get('set-cookie') };
}
const login = async (email, orgId, password = 'demo1234') =>
  (await call('POST', '/auth/login', { body: { email, password, ...(orgId ? { orgId } : {}) } })).body?.token;
const code = (r) => [r.status, r.body?.error?.code];
const role = (userId, orgId = 'org_acme') =>
  db.prepare('SELECT role, status FROM memberships WHERE user_id = ? AND org_id = ?').get(userId, orgId);

// A fresh org owned by dana, with extra members invited and accepted. Returns tokens.
async function orgWith(members) {
  const dana = await login('dana@example.test');
  const org = (await call('POST', '/orgs', { token: dana, body: { name: `probe-${Math.random()}` } })).body.id;
  const owner = (await call('POST', '/auth/token', { token: dana, body: { orgId: org } })).body.token;
  for (const [email, r] of members) {
    const inv = await call('POST', `/orgs/${org}/invites`, { token: owner, body: { email, role: r } });
    await call('POST', `/invites/${inv.body.inviteToken}/accept`, { body: { password: 'demo1234' } });
  }
  return { org, owner };
}

try {
  const dana = await login('dana@example.test');
  const admin = await login('admin@acme.test');
  const sam = await login('sam@example.test');

  console.log('\n== rank rules ==');
  const { org, owner } = await orgWith([['admin@acme.test', 'admin'], ['owner@globex.test', 'admin'], ['sam@example.test', 'operator']]);
  const adm = await login('admin@acme.test', org);
  check('admin -> admin (equal, not top) -> 403', code(await call('PATCH', `/orgs/${org}/members/usr_globex_owner`, { token: adm, body: { role: 'viewer' } })), [403, 'FORBIDDEN']);
  check('admin assigns admin -> 403', code(await call('PATCH', `/orgs/${org}/members/usr_sam`, { token: adm, body: { role: 'admin' } })), [403, 'FORBIDDEN']);
  check('admin demotes operator -> 200', (await call('PATCH', `/orgs/${org}/members/usr_sam`, { token: adm, body: { role: 'viewer' } })).status, 200);
  check('admin assigns the personalised role (below admin) -> 200',
    (await call('PATCH', `/orgs/${org}/members/usr_sam`, { token: adm, body: { role: db.prepare('SELECT key FROM roles WHERE rank > 30 AND rank < 40').get()?.key ?? 'operator' } })).status, 200);
  check('unknown role -> 400', (await call('PATCH', `/orgs/${org}/members/usr_sam`, { token: adm, body: { role: 'wizard' } })).status, 400);
  check('operator changes a role -> 403', (await call('PATCH', '/orgs/org_acme/members/usr_acme_viewer', { token: sam, body: { role: 'auditor' } })).status, 403);
  check('member of another org -> 404', (await call('PATCH', `/orgs/${org}/members/usr_acme_viewer`, { token: owner, body: { role: 'viewer' } })).status, 404);
  check('one refusal writes one deny row',
    db.prepare("SELECT count(*) n FROM audit_events WHERE org_id = ? AND action = 'member.role' AND result = 'deny'").get(org).n, 2);

  console.log('\n== last owner ==');
  check('owner suspends self -> 403', (await call('POST', `/orgs/${org}/members/usr_dana/suspend`, { token: owner })).status, 403);
  check('only owner leaves -> 409 LAST_OWNER', code(await call('DELETE', `/orgs/${org}/members/me`, { token: owner })), [409, 'LAST_OWNER']);
  check('an admin can leave', (await call('DELETE', `/orgs/${org}/members/me`, { token: await login('owner@globex.test', org) })).status, 204);

  console.log('\n== remove: tenancy cascade ==');
  const view = await call('POST', '/orgs/org_acme/sessions', { token: await login('viewer@acme.test'), body: { deviceId: 'dev_lab_mac_01', mode: 'view' } });
  const viewerOld = await login('viewer@acme.test');
  check('owner removes viewer -> 204', (await call('DELETE', '/orgs/org_acme/members/usr_acme_viewer', { token: dana })).status, 204);
  check('  ...their session ended: membership_removed', db.prepare('SELECT end_reason FROM sessions WHERE id = ?').get(view.body.id).end_reason, 'membership_removed');
  check('  ...their grants revoked', db.prepare("SELECT count(*) n FROM grants WHERE user_id = 'usr_acme_viewer' AND org_id = 'org_acme' AND revoked_at IS NULL").get().n, 0);
  check('  ...old token -> 401', (await call('GET', '/orgs/org_acme/devices', { token: viewerOld })).status, 401);
  check('  ...user row still exists (D15)', db.prepare("SELECT count(*) n FROM users WHERE id = 'usr_acme_viewer'").get().n, 1);
  check('  ...not in the member list', (await call('GET', '/orgs/org_acme/members', { token: dana })).body.members.some((m) => m.userId === 'usr_acme_viewer'), false);

  console.log('\n== invites ==');
  const inv = await call('POST', '/orgs/org_acme/invites', { token: dana, body: { email: '  Viewer@ACME.test ', role: 'viewer' } });
  check('re-invite removed person (email trimmed, lowercased)', [inv.status, inv.body.email], [201, 'viewer@acme.test']);
  check('second live invite, same email -> 409', (await call('POST', '/orgs/org_acme/invites', { token: dana, body: { email: 'viewer@acme.test', role: 'viewer' } })).status, 409);
  check('invite an active member -> 409', (await call('POST', '/orgs/org_acme/invites', { token: dana, body: { email: 'sam@example.test', role: 'viewer' } })).status, 409);
  check('admin invites as owner -> 403', (await call('POST', '/orgs/org_acme/invites', { token: admin, body: { email: 'x@example.test', role: 'owner' } })).status, 403);
  check('existing user, wrong password -> 401', (await call('POST', `/invites/${inv.body.inviteToken}/accept`, { body: { password: 'nope-nope' } })).status, 401);
  const back = await call('POST', `/invites/${inv.body.inviteToken}/accept`, { body: { name: 'ignored', password: 'demo1234' } });
  check('existing user, right password -> 200, viewer again', [back.status, back.body.role], [200, 'viewer']);
  check('  ...and is signed in (token + refresh cookie)', [typeof back.body.token, !!back.cookie], ['string', true]);
  check('  ...no duplicate user row', db.prepare("SELECT count(*) n FROM users WHERE email = 'viewer@acme.test'").get().n, 1);
  check('  ...old grants did not come back', db.prepare("SELECT count(*) n FROM grants WHERE user_id = 'usr_acme_viewer' AND org_id = 'org_acme' AND revoked_at IS NULL").get().n, 0);

  const attach = await call('POST', '/orgs/org_acme/invites', { token: dana, body: { email: 'owner@globex.test', role: 'auditor' } });
  const noPw = await call('POST', `/invites/${attach.body.inviteToken}/accept`, { body: {} });
  check('existing user, no password -> 200, attached', [noPw.status, noPw.body.role, role('usr_globex_owner')?.status], [200, 'auditor', 'active']);
  check('  ...but not signed in: no token, no cookie', ['token' in noPw.body, noPw.cookie, noPw.body.signedIn], [false, null, false]);
  check('  ...no duplicate user row', db.prepare("SELECT count(*) n FROM users WHERE email = 'owner@globex.test'").get().n, 1);

  const old = await call('POST', '/orgs/org_acme/invites', { token: dana, body: { email: 'late@example.test', role: 'viewer' } });
  db.prepare("UPDATE invites SET expires_at = '2020-01-01T00:00:00.000Z' WHERE id = ?").run(old.body.id);
  check('expired invite: peek -> 410', (await call('GET', `/invites/${old.body.inviteToken}`)).status, 410);
  check('  ...accept -> 410', (await call('POST', `/invites/${old.body.inviteToken}/accept`, { body: { name: 'L', password: 'longenough' } })).status, 410);
  check('  ...same email can be invited again', (await call('POST', '/orgs/org_acme/invites', { token: dana, body: { email: 'late@example.test', role: 'viewer' } })).status, 201);
  const cancel = await call('POST', '/orgs/org_acme/invites', { token: dana, body: { email: 'gone@example.test', role: 'viewer' } });
  check('cancel -> 204', (await call('DELETE', `/orgs/org_acme/invites/${cancel.body.id}`, { token: dana })).status, 204);
  check('  ...peek -> 410', (await call('GET', `/invites/${cancel.body.inviteToken}`)).status, 410);
  check('  ...cancel again -> 404', (await call('DELETE', `/orgs/org_acme/invites/${cancel.body.id}`, { token: dana })).status, 404);
  check('token stored hashed', db.prepare('SELECT count(*) n FROM invites WHERE token_hash = ?').get(cancel.body.inviteToken).n, 0);
  check('short password -> 400', (await call('POST', `/invites/${(await call('POST', '/orgs/org_acme/invites', { token: dana, body: { email: 'short@example.test', role: 'viewer' } })).body.inviteToken}/accept`, { body: { name: 'S', password: 'abc' } })).status, 400);

  console.log('\n== races across two processes ==');
  let acceptWins = 0;
  for (let i = 0; i < 5; i++) {
    const r = await call('POST', '/orgs/org_acme/invites', { token: dana, body: { email: `race${i}@example.test`, role: 'viewer' } });
    const body = { name: 'Racer', password: 'longenough' };
    const res = await Promise.all(PORTS.map((port) => call('POST', `/invites/${r.body.inviteToken}/accept`, { body, port })));
    const users = db.prepare('SELECT count(*) n FROM users WHERE email = ?').get(`race${i}@example.test`).n;
    if (JSON.stringify(res.map((x) => x.status).sort()) === '[200,409]' && users === 1) acceptWins++;
    else console.log(`        accept round ${i}: ${res.map((x) => `${x.status} ${x.body?.error?.code ?? ''}`)}, users ${users}`);
  }
  check('5 rounds of two parallel accepts: one 200, one 409', acceptWins, 5);

  let ownersKept = 0;
  for (let i = 0; i < 5; i++) {
    const { org: o, owner: a } = await orgWith([['owner@acme.test', 'owner']]);
    const b = await login('owner@acme.test', o);
    const [ra, rb] = await Promise.all([
      call('PATCH', `/orgs/${o}/members/usr_acme_owner`, { token: a, body: { role: 'viewer' }, port: PORTS[0] }),
      call('PATCH', `/orgs/${o}/members/usr_dana`, { token: b, body: { role: 'viewer' }, port: PORTS[1] }),
    ]);
    const owners = db.prepare("SELECT count(*) n FROM memberships WHERE org_id = ? AND role = 'owner' AND status = 'active'").get(o).n;
    const wins = [ra, rb].filter((r) => r.status === 200).length;
    if (owners === 1 && wins === 1) ownersKept++;
    else console.log(`        demote round ${i}: ${code(ra)} ${code(rb)}, owners ${owners}`);
  }
  check('5 rounds of two owners demoting each other: one wins, 1 owner left', ownersKept, 5);
} finally {
  for (const s of servers) s.kill();
  db.close();
  await new Promise((r) => setTimeout(r, 300));
  for (const s of ['', '-wal', '-shm']) rmSync(DB + s, { force: true });
}

console.log(`\n${fail === 0 ? 'ALL PASS' : 'FAILURES'} — ${pass} passed, ${fail} failed\n`);
process.exit(fail === 0 ? 0 : 1);
