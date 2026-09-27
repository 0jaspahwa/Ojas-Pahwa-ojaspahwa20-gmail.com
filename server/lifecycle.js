// Shared domain rules: role ranks, last-owner protection, ending sessions.
//
// The rules more than one route needs, so "what ends a session" has exactly one
// implementation. Sources: PERMISSIONS.md §6-7 and D8.
//
// - `roles.rank` is modification authority only. It never answers a can() question.
// - A permission change does not end a session in flight (grandfathering). Suspension,
//   membership removal and device transfer do.

import { badRequest, forbidden, lastOwner } from './http.js';

// Modification authority (D8). Read from the roles table: "owner" here means the
// top-ranked role, so no role name is written into these rules.
export function roleRanks(db) {
  return new Map(db.prepare('SELECT key, rank FROM roles').all().map((r) => [r.key, r.rank]));
}

const topRank = (ranks) => Math.max(...ranks.values());

export function assertRoleExists(db, role) {
  if (typeof role !== 'string' || !roleRanks(db).has(role)) throw badRequest('unknown role');
}

// You may act on a strictly lower role. The top role may also act on its equals:
// otherwise a co-owner could never be demoted (check-api: "demoting a NON-last owner").
export function assertCanModify(db, callerRole, targetRole) {
  const ranks = roleRanks(db);
  const caller = ranks.get(callerRole);
  const target = ranks.get(targetRole);
  if (caller > target || (caller === target && caller === topRank(ranks))) return;
  throw forbidden(`a ${callerRole} cannot modify a ${targetRole}`, 'rank');
}

// You may hand out a role below your own. Only the top role may hand out the top role.
export function assertCanAssign(db, callerRole, newRole) {
  const ranks = roleRanks(db);
  const caller = ranks.get(callerRole);
  const wanted = ranks.get(newRole);
  if (wanted < caller || caller === topRank(ranks)) return;
  throw forbidden(`a ${callerRole} cannot assign ${newRole}`, 'rank');
}

// Refuse a change that would leave no active member holding the top role.
// Call inside an IMMEDIATE transaction, so the count and the write share one write lock
// and a racing request re-counts after the winner commits.
export function assertNotLastOwner(db, orgId, userId) {
  const ranks = roleRanks(db);
  const top = [...ranks].find(([, rank]) => rank === topRank(ranks))[0];
  const m = db.prepare('SELECT role, status FROM memberships WHERE org_id = ? AND user_id = ?').get(orgId, userId);
  if (!m || m.role !== top || m.status !== 'active') return;
  const { n } = db.prepare(
    "SELECT count(*) AS n FROM memberships WHERE org_id = ? AND role = ? AND status = 'active'"
  ).get(orgId, top);
  if (n <= 1) throw lastOwner();
}
// The one place a session is ended. Filters are optional: pass userId, deviceId or both.
// Returns how many sessions were ended.
export function endActiveSessions(db, { orgId, userId = null, deviceId = null, reason, exceptSessionId = null }) {
  return db.prepare(
    `UPDATE sessions
        SET state = 'ended', end_reason = ?, ended_at = strftime('%Y-%m-%dT%H:%M:%fZ','now')
      WHERE org_id = ? AND state IN ('connecting', 'active')
        AND (? IS NULL OR user_id = ?)
        AND (? IS NULL OR device_id = ?)
        AND (? IS NULL OR id <> ?)`
  ).run(reason, orgId, userId, userId, deviceId, deviceId, exceptSessionId, exceptSessionId).changes;
}
// What a session was started on. Stored in sessions.authorized_by and never updated:
// this snapshot, not the live permission set, is the session's authority (grandfathering).
// Takes the set assertCanStartSession already resolved, so nothing is resolved twice.
export function snapshotAuthority({ role, mode, permission, set }) {
  return JSON.stringify({
    role,
    mode,
    'session:start': set['session:start'],
    [permission]: set[permission],
    at: new Date().toISOString(),
  });
}

// started_at + the org's max_session_minutes. Every session has an end.
// Pass the same startedAt you insert: two clocks (JS and SQLite's default) drift apart.
export function sessionExpiry(db, orgId, startedAt) {
  const { max_session_minutes: minutes } = db.prepare(
    'SELECT max_session_minutes FROM organizations WHERE id = ?'
  ).get(orgId);
  return new Date(Date.parse(startedAt) + minutes * 60_000).toISOString();
}

// Sessions past expires_at still read 'active' until something ends them. Call this
// before reading sessions, and before inserting one (an expired exclusive session
// would otherwise still hold the unique index).
export function expireSessions(db, { orgId = null, deviceId = null }) {
  return db.prepare(
    `UPDATE sessions
        SET state = 'ended', end_reason = 'session_expired', ended_at = expires_at
      WHERE state IN ('connecting', 'active')
        AND expires_at <= strftime('%Y-%m-%dT%H:%M:%fZ','now')
        AND (? IS NULL OR org_id = ?)
        AND (? IS NULL OR device_id = ?)`
  ).run(orgId, orgId, deviceId, deviceId).changes;
}
