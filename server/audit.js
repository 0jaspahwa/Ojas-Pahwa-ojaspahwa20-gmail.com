// Append-only audit writes.
//
// audit_events has BEFORE UPDATE / BEFORE DELETE triggers, so this module only INSERTs.
// - Denied attempts are recorded, not only successes.
// - One action, one row. The success row is written by the route, inside the same
//   transaction as the change. auditDenials() only ever writes 'deny' rows.

import { newId } from './db.js';
import { HttpError } from './http.js';

const inserts = new WeakMap(); // one prepared INSERT per connection

export function audit(db, { orgId, actorId, action, targetType = null, targetId = null, result, reasonCode = null, requestId = null }) {
  if (!inserts.has(db)) {
    inserts.set(db, db.prepare(
      `INSERT INTO audit_events (id, org_id, actor_id, action, target_type, target_id, result, reason_code, request_id)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`
    ));
  }
  inserts.get(db).run(newId('aud'), orgId, actorId, action, targetType, targetId, result, reasonCode, requestId);
}

// Run fn(). If it refuses with a 403, record the denial, then rethrow.
// fn must be synchronous: a rejected promise would slip past this catch.
export function auditDenials(db, ctx, meta, fn) {
  try {
    return fn();
  } catch (err) {
    if (err instanceof HttpError && err.status === 403) {
      audit(db, {
        orgId: ctx.orgId, actorId: ctx.userId, requestId: ctx.requestId, ...meta,
        result: 'deny', reasonCode: err.reason ?? err.code,
      });
    }
    throw err;
  }
}
