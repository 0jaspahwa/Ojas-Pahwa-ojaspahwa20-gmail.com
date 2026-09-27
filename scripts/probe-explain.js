// The "why?" inspector cannot disagree with the real decision.
//
// For every membership (any status) x every permission x every device in that org, plus
// the org level: explain().decision must deep-equal resolve().permissions[p].
// Runs on a fresh database with the personalised org, plus grants added here so every
// trace branch is hit: expired, not started, active window, wildcards, device-scoped
// allow and deny, a deleted device, a suspended member and a removed one.
//
//   node scripts/probe-explain.js

import { execFileSync } from 'node:child_process';
import { rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { isDeepStrictEqual } from 'node:util';
import { openDatabase } from '../server/db.js';
import { resolve, explain } from '../server/permissions.js';

const DB = join(tmpdir(), `probe-explain-${process.pid}.db`);
execFileSync(process.execPath, ['scripts/load-db.js'], { env: { ...process.env, DATABASE_FILE: DB }, stdio: 'ignore' });
const db = openDatabase(DB);
const now = new Date();
const at = (hours) => new Date(now.getTime() + hours * 3600_000).toISOString();

let n = 0;
function grant(orgId, userId, deviceId, effect, perms, startsAt = null, expiresAt = null) {
  const id = `grt_probe_${++n}`;
  db.prepare(`INSERT INTO grants (id, org_id, user_id, device_id, effect, starts_at, expires_at, created_by)
              VALUES (?, ?, ?, ?, ?, ?, ?, ?)`).run(id, orgId, userId, deviceId, effect, startsAt, expiresAt, userId);
  for (const p of perms) db.prepare('INSERT INTO grant_permissions (grant_id, permission) VALUES (?, ?)').run(id, p);
}

const firstDevice = (orgId) => db.prepare('SELECT id FROM devices WHERE org_id = ? ORDER BY id').get(orgId).id;
grant('org_acme', 'usr_acme_viewer', null, 'allow', ['*'], null, at(-1));                            // expired
grant('org_acme', 'usr_sam', firstDevice('org_acme'), 'deny', ['device:*'], at(+1), null);          // not started
grant('org_acme', 'usr_sam', null, 'allow', ['audit:read'], at(-1), at(+1));                          // active window
grant('org_globex', 'usr_dana', firstDevice('org_globex'), 'deny', ['session:*'], null, null);        // wildcard, device
grant('org_acme', 'usr_acme_admin', null, 'deny', ['user:*'], null, null);                            // wildcard, org-wide
db.prepare("INSERT INTO devices (id, org_id, name, kind, deleted_at) VALUES ('dev_probe_gone', 'org_acme', 'gone', 'linux', ?)").run(at(-1));
grant('org_acme', 'usr_acme_viewer', 'dev_probe_gone', 'allow', ['device:control'], null, null);      // deleted device
db.prepare("UPDATE memberships SET status = 'suspended' WHERE user_id = 'usr_sam' AND org_id = 'org_globex'").run();
db.prepare("UPDATE memberships SET status = 'removed' WHERE user_id = 'usr_acme_owner' AND org_id = 'org_acme'").run();

const catalogue = db.prepare('SELECT key FROM permissions ORDER BY key').all().map((r) => r.key);
const members = db.prepare('SELECT user_id, org_id, status FROM memberships ORDER BY org_id, user_id').all();

let checked = 0;
const drift = [];
for (const m of members) {
  const devices = [null, ...db.prepare('SELECT id FROM devices WHERE org_id = ? AND deleted_at IS NULL ORDER BY id').all(m.org_id).map((d) => d.id)];
  for (const deviceId of devices) {
    const truth = resolve(db, { userId: m.user_id, orgId: m.org_id, deviceId, now }).permissions;
    for (const permission of catalogue) {
      const { decision } = explain(db, { userId: m.user_id, orgId: m.org_id, permission, deviceId, now });
      checked++;
      if (!isDeepStrictEqual(decision, truth[permission])) {
        drift.push({ user: m.user_id, org: m.org_id, deviceId, permission, explain: decision, resolve: truth[permission] });
      }
    }
  }
}

// Every trace branch was reached at least once, or the comparison proves less than it seems.
const steps = new Set();
for (const m of members) {
  for (const permission of catalogue) {
    for (const deviceId of [null, firstDevice(m.org_id)]) {
      for (const s of explain(db, { userId: m.user_id, orgId: m.org_id, permission, deviceId, now }).trace) {
        steps.add(s.step === 'grants' ? 'grants' : `${s.step}${s.step === 'membership' ? `:${s.result}` : ''}`);
        for (const c of s.considered ?? []) steps.add(`grant:${c.window}/${c.scope}`);
      }
    }
  }
}

db.close();
for (const s of ['', '-wal', '-shm']) rmSync(DB + s, { force: true });

const orgs = new Set(members.map((m) => m.org_id)).size;
console.log(`\n  ${members.length} memberships in ${orgs} orgs x ${catalogue.length} permissions x (org level + each device)`);
console.log(`  trace branches reached: ${[...steps].sort().join(', ')}`);
for (const d of drift.slice(0, 5)) console.log(' DRIFT', JSON.stringify(d));
console.log(`\n${drift.length === 0 ? 'ALL PASS' : 'FAILURES'} — ${checked - drift.length} agreed, ${drift.length} disagreed (${checked} checked)\n`);
process.exit(drift.length === 0 ? 0 : 1);
