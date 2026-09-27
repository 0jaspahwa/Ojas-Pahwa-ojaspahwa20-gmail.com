// Orgs, members, and effective permissions.
//
// Every member change runs in an IMMEDIATE transaction: it takes the write lock first,
// so a racing request waits, then re-counts and gets a clean 409 LAST_OWNER. Without it,
// WAL snapshot isolation still stops a double win, but the loser fails with
// SQLITE_BUSY_SNAPSHOT, a 500 (measured: scripts/probe-members.js).

import { resolve, assertCan } from '../permissions.js';
import { audit, auditDenials } from '../audit.js';
import {
  assertRoleExists, assertCanModify, assertCanAssign, assertNotLastOwner, endActiveSessions,
} from '../lifecycle.js';
import { newId, bumpPermVersion } from '../db.js';
import { send, badRequest, notFound, forbidden, conflict, selfRoleChange } from '../http.js';

const THEME = /^[a-z]{1,20}$/;

export function registerOrgRoutes(router, { db }) {
  const activeOrgs = db.prepare(
    `SELECT o.id, o.name, o.theme, m.role
       FROM memberships m JOIN organizations o ON o.id = m.org_id
      WHERE m.user_id = ? AND m.status = 'active' AND o.deleted_at IS NULL
      ORDER BY m.joined_at, o.id`
  );
  const memberOf = db.prepare(
    "SELECT user_id, role, status FROM memberships WHERE org_id = ? AND user_id = ? AND status IN ('active', 'suspended')"
  );

  const record = (ctx, meta, extra = {}) =>
    audit(db, { orgId: ctx.orgId, actorId: ctx.userId, requestId: ctx.requestId, ...meta, result: 'allow', ...extra });

  // --- orgs ----------------------------------------------------------------------------

  router.get('/v1/orgs', (ctx, _p, res) => {
    send(res, 200, { orgs: activeOrgs.all(ctx.userId) });
  });

  // Any signed-in user may create an org and becomes its only owner (the top role).
  // The caller's token stays scoped to its org: switching needs POST /auth/token.
  router.post('/v1/orgs', (ctx, _p, res) => {
    const name = typeof ctx.body.name === 'string' ? ctx.body.name.trim() : '';
    if (!name || name.length > 100) throw badRequest('name must be 1-100 characters');
    const theme = ctx.body.theme ?? 'slate';
    if (!THEME.test(theme)) throw badRequest('theme must be 1-20 lowercase letters');

    const top = db.prepare('SELECT key FROM roles ORDER BY rank DESC LIMIT 1').get().key;
    const id = newId('org');
    db.transaction(() => {
      db.prepare('INSERT INTO organizations (id, name, theme) VALUES (?, ?, ?)').run(id, name, theme);
      db.prepare(
        `INSERT INTO memberships (id, org_id, user_id, role, status, joined_at)
         VALUES (?, ?, ?, ?, 'active', strftime('%Y-%m-%dT%H:%M:%fZ','now'))`
      ).run(newId('mem'), id, ctx.userId, top);
      audit(db, { orgId: id, actorId: ctx.userId, requestId: ctx.requestId, action: 'org.create',
                  targetType: 'org', targetId: id, result: 'allow' });
    })();
    send(res, 201, { id, name, theme, role: top });
  });

  router.patch('/v1/orgs/:org', (ctx, _p, res) => {
    const meta = { action: 'org.update', targetType: 'org', targetId: ctx.orgId };
    auditDenials(db, ctx, meta, () => assertCan(db, ctx, 'org:update'));
    const { name, theme } = ctx.body;
    if (name !== undefined && (typeof name !== 'string' || !name.trim() || name.trim().length > 100)) {
      throw badRequest('name must be 1-100 characters');
    }
    if (theme !== undefined && !THEME.test(theme)) throw badRequest('theme must be 1-20 lowercase letters');
    if (name === undefined && theme === undefined) throw badRequest('nothing to update');

    db.transaction(() => {
      db.prepare('UPDATE organizations SET name = coalesce(?, name), theme = coalesce(?, theme) WHERE id = ?')
        .run(name?.trim() ?? null, theme ?? null, ctx.orgId);
      record(ctx, meta);
    })();
    send(res, 200, db.prepare('SELECT id, name, theme FROM organizations WHERE id = ?').get(ctx.orgId));
  });

  // Soft delete. Every token for this org then fails in context.js (org deleted -> 401).
  router.delete('/v1/orgs/:org', (ctx, _p, res) => {
    const meta = { action: 'org.delete', targetType: 'org', targetId: ctx.orgId };
    auditDenials(db, ctx, meta, () => assertCan(db, ctx, 'org:delete'));
    db.transaction(() => {
      db.prepare("UPDATE organizations SET deleted_at = strftime('%Y-%m-%dT%H:%M:%fZ','now') WHERE id = ?").run(ctx.orgId);
      endActiveSessions(db, { orgId: ctx.orgId, reason: 'membership_removed' });
      record(ctx, meta);
    })();
    send(res, 204);
  });

  // The role catalogue, for pickers. Read from the table, so the console has no list of its own.
  router.get('/v1/orgs/:org/roles', (_ctx, _p, res) => {
    send(res, 200, { roles: db.prepare('SELECT key, label, rank FROM roles ORDER BY rank DESC').all() });
  });

  // --- members ----------------------------------------------------------------------

  router.get('/v1/orgs/:org/members', (ctx, _p, res) => {
    auditDenials(db, ctx, { action: 'member.list', targetType: 'org', targetId: ctx.orgId }, () =>
      assertCan(db, ctx, 'user:read'));
    const members = db.prepare(
      `SELECT u.id AS userId, u.email, u.name, m.role, m.status, m.joined_at AS joinedAt
         FROM memberships m JOIN users u ON u.id = m.user_id
        WHERE m.org_id = ? AND m.status IN ('active', 'suspended')
        ORDER BY m.joined_at, u.id`
    ).all(ctx.orgId);
    send(res, 200, { members });
  });

  // Leave. Registered before /members/:userId so 'me' is not read as a user id.
  router.delete('/v1/orgs/:org/members/me', (ctx, _p, res) => {
    db.transaction(() => {
      assertNotLastOwner(db, ctx.orgId, ctx.userId);
      removeMembership(ctx, ctx.userId, { action: 'member.leave', targetType: 'user', targetId: ctx.userId });
    }).immediate();
    send(res, 204);
  });

  // The shared checks for acting on another member. Returns the target membership.
  // Order: permission (403) -> target visible (404) -> not yourself -> rank (403).
  // Not audited here: each route wraps it once, so one refusal is one deny row.
  function targetMember(ctx, userId, permission, selfError) {
    assertCan(db, ctx, permission);
    const target = memberOf.get(ctx.orgId, userId);
    if (!target) throw notFound();
    if (userId === ctx.userId) throw selfError();
    assertCanModify(db, ctx.role, target.role);
    return target;
  }

  // Role change. Grandfathered: running sessions are left alone; the token goes stale.
  router.patch('/v1/orgs/:org/members/:userId', (ctx, p, res) => {
    const meta = { action: 'member.role', targetType: 'user', targetId: p.userId };
    const role = ctx.body.role;
    const target = auditDenials(db, ctx, meta, () => {
      const t = targetMember(ctx, p.userId, 'user:role:update', selfRoleChange);
      assertRoleExists(db, role);
      assertCanAssign(db, ctx.role, role);
      return t;
    });

    db.transaction(() => {
      if (role !== target.role) assertNotLastOwner(db, ctx.orgId, p.userId);
      db.prepare('UPDATE memberships SET role = ? WHERE org_id = ? AND user_id = ?').run(role, ctx.orgId, p.userId);
      bumpPermVersion(db, { orgId: ctx.orgId, userId: p.userId });
      record(ctx, meta);
    }).immediate();
    send(res, 200, memberOf.get(ctx.orgId, p.userId));
  });

  const notSelf = (what) => () => forbidden(`you cannot ${what} yourself`, 'self');

  // Suspend: reversible. Ends their sessions in this org only.
  router.post('/v1/orgs/:org/members/:userId/suspend', (ctx, p, res) => {
    const meta = { action: 'member.suspend', targetType: 'user', targetId: p.userId };
    const target = auditDenials(db, ctx, meta, () => targetMember(ctx, p.userId, 'user:remove', notSelf('suspend')));
    if (target.status === 'suspended') throw conflict('already suspended');

    db.transaction(() => {
      assertNotLastOwner(db, ctx.orgId, p.userId);
      db.prepare("UPDATE memberships SET status = 'suspended' WHERE org_id = ? AND user_id = ?").run(ctx.orgId, p.userId);
      bumpPermVersion(db, { orgId: ctx.orgId, userId: p.userId });
      endActiveSessions(db, { orgId: ctx.orgId, userId: p.userId, reason: 'user_suspended' });
      record(ctx, meta);
    }).immediate();
    send(res, 200, memberOf.get(ctx.orgId, p.userId));
  });

  // Reinstate. The pv bump means tokens from before the suspension stay dead.
  router.delete('/v1/orgs/:org/members/:userId/suspend', (ctx, p, res) => {
    const meta = { action: 'member.reinstate', targetType: 'user', targetId: p.userId };
    const target = auditDenials(db, ctx, meta, () => targetMember(ctx, p.userId, 'user:remove', notSelf('reinstate')));
    if (target.status !== 'suspended') throw conflict('not suspended');

    db.transaction(() => {
      db.prepare("UPDATE memberships SET status = 'active' WHERE org_id = ? AND user_id = ?").run(ctx.orgId, p.userId);
      bumpPermVersion(db, { orgId: ctx.orgId, userId: p.userId });
      record(ctx, meta);
    }).immediate();
    send(res, 200, memberOf.get(ctx.orgId, p.userId));
  });

  router.delete('/v1/orgs/:org/members/:userId', (ctx, p, res) => {
    const meta = { action: 'member.remove', targetType: 'user', targetId: p.userId };
    auditDenials(db, ctx, meta, () => targetMember(ctx, p.userId, 'user:remove', notSelf('remove')));
    db.transaction(() => {
      assertNotLastOwner(db, ctx.orgId, p.userId);
      removeMembership(ctx, p.userId, meta);
    }).immediate();
    send(res, 204);
  });

  // Removal: the user row and their other orgs are untouched (D15). Their grants here
  // are revoked, or they would come back if the person were ever invited again.
  function removeMembership(ctx, userId, meta) {
    db.prepare("UPDATE memberships SET status = 'removed' WHERE org_id = ? AND user_id = ?").run(ctx.orgId, userId);
    db.prepare(
      `UPDATE grants SET revoked_at = strftime('%Y-%m-%dT%H:%M:%fZ','now')
        WHERE org_id = ? AND user_id = ? AND revoked_at IS NULL`
    ).run(ctx.orgId, userId);
    bumpPermVersion(db, { orgId: ctx.orgId, userId });
    endActiveSessions(db, { orgId: ctx.orgId, userId, reason: 'membership_removed' });
    record(ctx, meta);
  }

  // --- effective permissions ----------------------------------------------------------

  // user:read, or yourself. ?deviceId= asks the device-level question.
  router.get('/v1/orgs/:org/users/:userId/effective', (ctx, p, res) => {
    const meta = { action: 'member.effective', targetType: 'user', targetId: p.userId };
    if (p.userId !== ctx.userId) auditDenials(db, ctx, meta, () => assertCan(db, ctx, 'user:read'));
    if (!memberOf.get(ctx.orgId, p.userId)) throw notFound();
    const deviceId = ctx.query.get('deviceId');
    if (deviceId !== null && !db.prepare('SELECT 1 FROM devices WHERE id = ? AND org_id = ? AND deleted_at IS NULL').get(deviceId, ctx.orgId)) {
      throw notFound();
    }
    const { role, permissions } = resolve(db, { userId: p.userId, orgId: ctx.orgId, deviceId });
    send(res, 200, { userId: p.userId, deviceId, role, permissions });
  });
}
