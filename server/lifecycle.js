// Shared domain rules: role ranks, last-owner protection, ending sessions.
//
// YOURS TO WRITE. This file ships as a stub.
//
// Put here the rules more than one route needs, so "what ends a session" has exactly
// one implementation. Sources: PERMISSIONS.md §7.2 and D8.
//
// Two traps worth naming before you start:
//   - `roles.rank` is MODIFICATION AUTHORITY ONLY. It must never answer a can()
//     question. operator and auditor are unordered by permission, and ranking them is
//     the modelling error the auditor role exists to catch.
//   - a permission change does NOT end a session in flight (grantfathering). Suspension,
//     membership removal and device transfer DO. See PERMISSIONS.md §7.

const todo = (name) =>
  Object.assign(
    new Error(`TODO: server/lifecycle.js — ${name}() is yours to write (BRIEF.md §3).`),
    { code: 'NOT_IMPLEMENTED' }
  );

export function roleRanks(db) { throw todo('roleRanks'); }
export function assertRoleExists(db, role) { throw todo('assertRoleExists'); }
export function assertCanModify(db, callerRole, targetRole) { throw todo('assertCanModify'); }
export function assertNotLastOwner(db, orgId, userId) { throw todo('assertNotLastOwner'); }
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
