// Probes for engine cases the shipped suites do not cover.
// Works on a throwaway copy of app.db, so run `npm run db:reset` first.
//
//   node scripts/probe-engine.js

import { rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { openDatabase } from '../server/db.js';
import { resolve, assertMayGrant } from '../server/permissions.js';

const file = join(tmpdir(), `probe-${process.pid}.db`);
openDatabase('app.db').exec(`VACUUM INTO '${file.replaceAll("'", "''")}'`);
const db = openDatabase(file);

let pass = 0, fail = 0;
const check = (label, got, want) => {
  const ok = got === want;
  ok ? pass++ : fail++;
  console.log(`${ok ? ' ok  ' : ' FAIL'}  ${label.padEnd(58)} ${ok ? '' : `got ${got} want ${want}`}`);
};

const userId = (email) => db.prepare('SELECT id FROM users WHERE email = ?').get(email).id;
const effect = (uid, orgId, perm, deviceId = null, now = new Date()) =>
  resolve(db, { userId: uid, orgId, deviceId, now }).permissions[perm].effect;
const mayGrant = (uid, orgId, perm, deviceId) => {
  try { assertMayGrant(db, { userId: uid, orgId }, [perm], deviceId); return 'allowed'; }
  catch (e) { return `refused ${e.status}`; }
};

const org = 'org_acme';
const owner = userId('owner@acme.test');
const admin = userId('admin@acme.test');
const viewer = userId('viewer@acme.test');
const [dev0, dev1] = db.prepare('SELECT id FROM devices WHERE org_id = ? AND deleted_at IS NULL ORDER BY id LIMIT 2')
  .all(org).map((r) => r.id);
const otherOrg = db.prepare('SELECT id FROM organizations WHERE id <> ? ORDER BY id LIMIT 1').get(org).id;

let n = 0;
const grant = (uid, deviceId, eff, perm, expiresAt = null) => {
  const id = `grt_probe_${++n}`;
  db.prepare(`INSERT INTO grants (id, org_id, user_id, device_id, effect, expires_at, created_by)
              VALUES (?, ?, ?, ?, ?, ?, ?)`).run(id, org, uid, deviceId, eff, expiresAt, owner);
  db.prepare('INSERT INTO grant_permissions (grant_id, permission) VALUES (?, ?)').run(id, perm);
};

try {
  console.log('\n== laundering: an org-wide grant needs the permission on every device ==');
  grant(viewer, null, 'allow', 'grant:create');
  grant(viewer, dev0, 'allow', 'device:control');
  check('one-device holder grants org-wide', mayGrant(viewer, org, 'device:control', null), 'refused 403');
  check('one-device holder grants on that device', mayGrant(viewer, org, 'device:control', dev0), 'allowed');
  grant(admin, dev1, 'deny', 'device:terminal');
  check('admin denied on one device grants org-wide', mayGrant(admin, org, 'device:terminal', null), 'refused 403');
  check('admin denied on one device grants on another', mayGrant(admin, org, 'device:terminal', dev0), 'allowed');

  console.log('\n== org-level nav is the union ==');
  check('admin nav keeps terminal despite a one-device deny', effect(admin, org, 'device:terminal'), 'allow');
  check('viewer nav shows control from a one-device allow', effect(viewer, org, 'device:control'), 'allow');
  // The personalised pair: one device-scoped allow and one device-scoped deny of the same
  // permission, same user. Found by shape, not by name, so it works for any nonce.
  const pairs = db.prepare(
    `SELECT a.user_id, a.org_id, a.device_id AS allow_dev, d.device_id AS deny_dev, ap.permission
       FROM grants a JOIN grant_permissions ap ON ap.grant_id = a.id
       JOIN grants d ON d.user_id = a.user_id AND d.org_id = a.org_id
       JOIN grant_permissions dp ON dp.grant_id = d.id AND dp.permission = ap.permission
      WHERE a.effect = 'allow' AND d.effect = 'deny'
        AND a.device_id IS NOT NULL AND d.device_id IS NOT NULL AND a.device_id <> d.device_id`
  ).all();
  for (const pair of pairs) {
    check(`${pair.permission} org-level`, effect(pair.user_id, pair.org_id, pair.permission), 'allow');
    check(`${pair.permission} on the allowed device`, effect(pair.user_id, pair.org_id, pair.permission, pair.allow_dev), 'allow');
    check(`${pair.permission} on the denied device`, effect(pair.user_id, pair.org_id, pair.permission, pair.deny_dev), 'deny');
  }

  console.log('\n== a transferred device stops granting in its old org ==');
  db.prepare('UPDATE devices SET org_id = ? WHERE id = ?').run(otherOrg, dev0);
  check('viewer nav control after transfer', effect(viewer, org, 'device:control'), 'deny');

  console.log('\n== half-open window, compared as instants ==');
  grant(viewer, null, 'allow', 'audit:read', '2030-01-01T09:00:00Z');
  check('1 ms before expiry', effect(viewer, org, 'audit:read', null, new Date('2030-01-01T08:59:59.999Z')), 'allow');
  check('at expiry, written without ms', effect(viewer, org, 'audit:read', null, new Date('2030-01-01T09:00:00.000Z')), 'deny');
} finally {
  db.close();
  for (const s of ['', '-wal', '-shm']) rmSync(file + s, { force: true });
}

console.log(`\n${fail === 0 ? 'ALL PASS' : 'FAILURES'} — ${pass} passed, ${fail} failed\n`);
process.exit(fail === 0 ? 0 : 1);
