// Probes for server/context.js: token -> caller.
// Works on a throwaway copy of app.db, so run `npm run db:reset` first.
//
//   node scripts/probe-context.js

import { rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { openDatabase } from '../server/db.js';
import { issueAccessToken, signToken } from '../server/auth.js';
import { authenticate } from '../server/context.js';

const SECRET = 'probe-secret';
const file = join(tmpdir(), `probe-ctx-${process.pid}.db`);
openDatabase('app.db').exec(`VACUUM INTO '${file.replaceAll("'", "''")}'`);
const db = openDatabase(file);
const build = authenticate(db, SECRET);

let pass = 0, fail = 0;
const check = (label, got, want) => {
  const ok = JSON.stringify(got) === JSON.stringify(want);
  ok ? pass++ : fail++;
  console.log(`${ok ? ' ok  ' : ' FAIL'}  ${label.padEnd(52)} ${ok ? '' : `got ${JSON.stringify(got)} want ${JSON.stringify(want)}`}`);
};

// Run buildContext and report "status CODE", or "ok" with the caller.
const run = (authorization, params = {}) => {
  try {
    const caller = build({ headers: authorization === undefined ? {} : { authorization } }, params);
    return { out: 'ok', caller };
  } catch (e) {
    return { out: `${e.status ?? 'NO STATUS'} ${e.code ?? e.name}`, message: e.message };
  }
};

const membership = (userId, orgId) =>
  db.prepare('SELECT role, perm_version FROM memberships WHERE user_id = ? AND org_id = ?').get(userId, orgId);
const tokenFor = (userId, orgId, pv = membership(userId, orgId).perm_version) =>
  issueAccessToken({ userId, orgId, role: membership(userId, orgId).role, permVersion: pv }, SECRET);
const bearer = (t) => `Bearer ${t}`;
const allows = (caller) => Object.values(caller.permissions).filter((p) => p.effect === 'allow').length;

try {
  const dana = tokenFor('usr_dana', 'org_acme');

  console.log('\n== the header ==');
  check('no Authorization header', run(undefined).out, '401 UNAUTHENTICATED');
  check('empty header', run('').out, '401 UNAUTHENTICATED');
  check('wrong scheme (Basic)', run(`Basic ${dana}`).out, '401 UNAUTHENTICATED');
  check('Bearer with no token', run('Bearer ').out, '401 UNAUTHENTICATED');

  console.log('\n== the token ==');
  check('wrong secret', run(bearer(issueAccessToken({ userId: 'usr_dana', orgId: 'org_acme', role: 'owner', permVersion: 1 }, 'nope'))).out, '401 UNAUTHENTICATED');
  check('tampered payload', run(bearer(dana.replace(/\.[^.]+\./, `.${Buffer.from('{"sub":"usr_dana"}').toString('base64url')}.`))).out, '401 UNAUTHENTICATED');

  console.log('\n== a good token ==');
  const ok = run(bearer(dana), { org: 'org_acme' });
  check('valid token builds a caller', ok.out, 'ok');
  check('  ...userId / orgId / role', [ok.caller?.userId, ok.caller?.orgId, ok.caller?.role], ['usr_dana', 'org_acme', 'owner']);
  // Not "owner has everything": a permission in no role's baseline is denied even for owner.
  const ownerBaseline = db.prepare("SELECT permission FROM role_permissions WHERE role = 'owner'").all().map((r) => r.permission);
  check('  ...permissions attached: owner baseline all allow', ownerBaseline.every((p) => ok.caller.permissions[p]?.effect === 'allow'), true);
  const outside = Object.keys(ok.caller.permissions).filter((p) => !ownerBaseline.includes(p));
  check('  ...a permission outside the baseline is implicit', outside.every((p) => ok.caller.permissions[p].reason === 'implicit'), true);
  check('lowercase "bearer" accepted', run(`bearer ${dana}`).out, 'ok');
  check('route with no :org param', run(bearer(dana), { id: 'ses_x' }).out, 'ok');

  console.log('\n== org in the path: 404, never 403 ==');
  const cross = run(bearer(dana), { org: 'org_globex' });
  const absent = run(bearer(dana), { org: 'org_does_not_exist' });
  check('Acme token on a Globex path', cross.out, '404 NOT_FOUND');
  check('  ...same as an org that does not exist', [cross.out, cross.message], [absent.out, absent.message]);

  console.log('\n== freshness ==');
  const pv = membership('usr_dana', 'org_acme').perm_version;
  check('pv one behind', run(bearer(tokenFor('usr_dana', 'org_acme', pv - 1))).out, '401 TOKEN_STALE');
  check('pv one ahead (from the future)', run(bearer(tokenFor('usr_dana', 'org_acme', pv + 1))).out, '401 TOKEN_STALE');

  console.log('\n== membership status ==');
  const samAcme = tokenFor('usr_sam', 'org_acme');
  db.prepare("UPDATE memberships SET status = 'suspended', perm_version = perm_version + 1 WHERE user_id = 'usr_sam' AND org_id = 'org_acme'").run();
  const susp = run(bearer(samAcme), { org: 'org_acme' });
  check('suspended (pv bumped): caller still built', susp.out, 'ok');
  check('  ...with zero allows', susp.caller && allows(susp.caller), 0);
  check('  ...reason is suspended', susp.caller?.permissions['device:list'].reason, 'suspended');
  check('  ...Sam in Globex is untouched', run(bearer(tokenFor('usr_sam', 'org_globex'))).caller?.role, 'auditor');

  db.prepare("UPDATE memberships SET status = 'removed' WHERE user_id = 'usr_sam' AND org_id = 'org_acme'").run();
  check('removed member', run(bearer(tokenFor('usr_sam', 'org_acme'))).out, '401 UNAUTHENTICATED');

  const never = signToken({ iss: 'remoteops', aud: 'remoteops-api', sub: 'usr_dana', org: 'org_nope', role: 'owner',
    pv: 1, jti: 'j', iat: 0, exp: Math.floor(Date.now() / 1000) + 60 }, SECRET);
  check('validly signed, but no membership', run(bearer(never)).out, '401 UNAUTHENTICATED');

  db.prepare("UPDATE organizations SET deleted_at = '2026-01-01T00:00:00.000Z' WHERE id = 'org_acme'").run();
  check('org soft-deleted', run(bearer(dana)).out, '401 UNAUTHENTICATED');
} finally {
  db.close();
  for (const s of ['', '-wal', '-shm']) rmSync(file + s, { force: true });
}

console.log(`\n${fail === 0 ? 'ALL PASS' : 'FAILURES'} — ${pass} passed, ${fail} failed\n`);
process.exit(fail === 0 ? 0 : 1);
