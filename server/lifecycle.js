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
export function snapshotAuthority(db, { userId, orgId, deviceId }) { throw todo('snapshotAuthority'); }
export function sessionExpiry(db, orgId) { throw todo('sessionExpiry'); }
