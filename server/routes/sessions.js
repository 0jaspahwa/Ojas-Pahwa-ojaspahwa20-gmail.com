// Sessions and the audit list.
//
// A session's authority is the snapshot taken at start. Permission changes never end
// one; suspension, removal, transfer and the TTL do (lifecycle.js).

import { assertCan, assertCanStartSession, MODE_PERMISSION } from '../permissions.js';
import { audit, auditDenials } from '../audit.js';
import { endActiveSessions, expireSessions, sessionExpiry, snapshotAuthority } from '../lifecycle.js';
import { newId } from '../db.js';
import { send, badRequest, notFound, conflict, deviceBusy } from '../http.js';

const SESSION_COLS = 'id, org_id, user_id, device_id, mode, state, end_reason, started_at, expires_at, ended_at';
const MAX_LIMIT = 500;

// Query-string integer: digits only, so '1.5', '1e3', '' and '-1' are all rejected.
function intParam(query, name, fallback, min, max) {
  const raw = query.get(name);
  if (raw === null) return fallback;
  if (!/^\d+$/.test(raw) || Number(raw) < min || Number(raw) > max) {
    throw badRequest(`${name} must be an integer from ${min} to ${max}`);
  }
  return Number(raw);
}

export function registerSessionRoutes(router, { db }) {
  const deviceIn = db.prepare('SELECT id FROM devices WHERE id = ? AND org_id = ? AND deleted_at IS NULL');
  const sessionById = db.prepare(`SELECT ${SESSION_COLS} FROM sessions WHERE id = ?`);
  const exclusiveHolder = db.prepare(
    "SELECT id FROM sessions WHERE device_id = ? AND state = 'active' AND mode IN ('control', 'terminal')"
  );

  router.post('/v1/orgs/:org/sessions', (ctx, _p, res) => {
    const { deviceId, mode } = ctx.body;
    if (!Object.hasOwn(MODE_PERMISSION, mode)) throw badRequest('mode must be view, control or terminal');
    if (typeof deviceId !== 'string' || !deviceIn.get(deviceId, ctx.orgId)) throw notFound();

    const meta = { action: 'session.start', targetType: 'device', targetId: deviceId };
    const set = auditDenials(db, ctx, meta, () => assertCanStartSession(db, ctx, mode, deviceId));

    const id = newId('ses');
    const startedAt = new Date().toISOString();
    try {
      db.transaction(() => {
        expireSessions(db, { deviceId });
        db.prepare(
          `INSERT INTO sessions (id, org_id, user_id, device_id, mode, state, authorized_by, started_at, expires_at)
           VALUES (?, ?, ?, ?, ?, 'active', ?, ?, ?)`
        ).run(id, ctx.orgId, ctx.userId, deviceId, mode,
              snapshotAuthority({ role: ctx.role, mode, permission: MODE_PERMISSION[mode], set }),
              startedAt, sessionExpiry(db, ctx.orgId, startedAt));
        audit(db, { orgId: ctx.orgId, actorId: ctx.userId, requestId: ctx.requestId, ...meta,
                    targetType: 'session', targetId: id, result: 'allow' });
      })();
    } catch (err) {
      // The partial unique index is the lock: no check-then-insert to race.
      if (err.code !== 'SQLITE_CONSTRAINT_UNIQUE') throw err;
      const holder = exclusiveHolder.get(deviceId);
      throw deviceBusy(`device is held by session ${holder?.id}`);
    }
    send(res, 201, sessionById.get(id));
  });

  router.get('/v1/orgs/:org/sessions', (ctx, _p, res) => {
    auditDenials(db, ctx, { action: 'session.list', targetType: 'org', targetId: ctx.orgId }, () =>
      assertCan(db, ctx, 'session:view'));
    expireSessions(db, { orgId: ctx.orgId });
    const sessions = db.prepare(
      `SELECT ${SESSION_COLS} FROM sessions WHERE org_id = ? ORDER BY started_at DESC, id LIMIT ?`
    ).all(ctx.orgId, MAX_LIMIT);
    send(res, 200, { sessions });
  });

  // Not under /orgs/:org, so context.js cannot check the org: it is checked here.
  // Another org's session, or one you may not read, is a 404.
  function readableSession(ctx, id) {
    const s = sessionById.get(id);
    if (!s || s.org_id !== ctx.orgId) throw notFound();
    if (s.user_id !== ctx.userId && ctx.permissions['session:view'].effect !== 'allow') throw notFound();
    if (expireSessions(db, { orgId: ctx.orgId, deviceId: s.device_id })) return sessionById.get(id);
    return s;
  }

  router.get('/v1/sessions/:id', (ctx, p, res) => {
    send(res, 200, readableSession(ctx, p.id));
  });

  router.delete('/v1/sessions/:id', (ctx, p, res) => {
    const s = readableSession(ctx, p.id);
    const own = s.user_id === ctx.userId;
    const meta = { action: own ? 'session.stop' : 'session.terminate', targetType: 'session', targetId: s.id };
    if (!own) auditDenials(db, ctx, meta, () => assertCan(db, ctx, 'session:terminate'));
    if (s.state === 'ended') throw conflict('session already ended');

    db.transaction(() => {
      db.prepare(
        `UPDATE sessions SET state = 'ended', end_reason = ?, ended_at = strftime('%Y-%m-%dT%H:%M:%fZ','now')
          WHERE id = ?`
      ).run(own ? 'user_stopped' : 'admin_terminated', s.id);
      audit(db, { orgId: ctx.orgId, actorId: ctx.userId, requestId: ctx.requestId, ...meta, result: 'allow' });
    })();
    send(res, 200, sessionById.get(s.id));
  });

  // --- audit list --------------------------------------------------------------------

  router.get('/v1/orgs/:org/audit', (ctx, _p, res) => {
    auditDenials(db, ctx, { action: 'audit.read', targetType: 'org', targetId: ctx.orgId }, () =>
      assertCan(db, ctx, 'audit:read'));
    const limit = intParam(ctx.query, 'limit', 50, 1, MAX_LIMIT);
    const offset = intParam(ctx.query, 'offset', 0, 0, Number.MAX_SAFE_INTEGER);
    const events = db.prepare(
      `SELECT id, org_id, actor_id, action, target_type, target_id, result, reason_code, request_id, at
         FROM audit_events WHERE org_id = ? ORDER BY at DESC, id DESC LIMIT ? OFFSET ?`
    ).all(ctx.orgId, limit, offset);
    send(res, 200, { events, limit, offset });
  });
}
