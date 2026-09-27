// Devices and grants.
//
// Visibility first, permission second: a device that is missing, deleted, in another
// org, or that you cannot device:view is a 404. Only a device you can see gets a 403.

import { resolve, resolveDevices, assertCan, assertAllowed, assertMayGrant } from '../permissions.js';
import { audit, auditDenials } from '../audit.js';
import { endActiveSessions } from '../lifecycle.js';
import { newId, bumpPermVersion } from '../db.js';
import { send, badRequest, notFound, forbidden, normalizeTs, HttpError } from '../http.js';

const KINDS = ['macos', 'windows', 'linux', 'android', 'ios'];

const row = (d, permissions) => ({ id: d.id, name: d.name, kind: d.kind, online: d.online === 1, permissions });

function validName(name) {
  if (typeof name !== 'string' || !name.trim() || name.trim().length > 100) {
    throw badRequest('name must be 1-100 characters');
  }
  return name.trim();
}

export function registerDeviceRoutes(router, { db }) {
  const listDevices = db.prepare(
    'SELECT id, name, kind, online FROM devices WHERE org_id = ? AND deleted_at IS NULL ORDER BY name, id'
  );
  const deviceIn = db.prepare(
    'SELECT id, name, kind, online FROM devices WHERE id = ? AND org_id = ? AND deleted_at IS NULL'
  );
  const activeMember = db.prepare(
    `SELECT 1 FROM memberships m JOIN organizations o ON o.id = m.org_id
      WHERE m.user_id = ? AND m.org_id = ? AND m.status = 'active' AND o.deleted_at IS NULL`
  );

  // The device and the caller's permissions on it, or 404.
  // A device you cannot view is invisible: the 404 is recorded as a denial, since
  // auditDenials only sees 403s.
  function visibleDevice(ctx, id, action) {
    const device = deviceIn.get(id, ctx.orgId);
    if (!device) throw notFound();
    const permissions = resolve(db, { userId: ctx.userId, orgId: ctx.orgId, deviceId: id }).permissions;
    if (permissions['device:view'].effect !== 'allow') {
      audit(db, { orgId: ctx.orgId, actorId: ctx.userId, requestId: ctx.requestId, action,
                  targetType: 'device', targetId: id, result: 'deny', reasonCode: 'not_visible' });
      throw notFound();
    }
    return { device, permissions };
  }

  // --- devices ---------------------------------------------------------------------

  // One query for the rows, one resolve for all of them. No query per row.
  router.get('/v1/orgs/:org/devices', (ctx, _p, res) => {
    auditDenials(db, ctx, { action: 'device.list', targetType: 'org', targetId: ctx.orgId }, () =>
      assertCan(db, ctx, 'device:list'));

    const devices = listDevices.all(ctx.orgId);
    const { byDevice } = resolveDevices(db, { userId: ctx.userId, orgId: ctx.orgId, deviceIds: devices.map((d) => d.id) });
    send(res, 200, {
      devices: devices
        .filter((d) => byDevice[d.id]['device:view'].effect === 'allow')
        .map((d) => row(d, byDevice[d.id])),
    });
  });

  router.get('/v1/orgs/:org/devices/:id', (ctx, p, res) => {
    const { device, permissions } = visibleDevice(ctx, p.id, 'device.view');
    send(res, 200, row(device, permissions));
  });

  router.post('/v1/orgs/:org/devices', (ctx, _p, res) => {
    const meta = { action: 'device.provision', targetType: 'org', targetId: ctx.orgId };
    auditDenials(db, ctx, meta, () => assertCan(db, ctx, 'device:provision'));

    const name = validName(ctx.body.name);
    if (!KINDS.includes(ctx.body.kind)) throw badRequest(`kind must be one of ${KINDS.join(', ')}`);

    const id = newId('dev');
    db.transaction(() => {
      db.prepare('INSERT INTO devices (id, org_id, name, kind) VALUES (?, ?, ?, ?)').run(id, ctx.orgId, name, ctx.body.kind);
      audit(db, { orgId: ctx.orgId, actorId: ctx.userId, requestId: ctx.requestId, action: 'device.provision',
                  targetType: 'device', targetId: id, result: 'allow' });
    })();

    const permissions = resolve(db, { userId: ctx.userId, orgId: ctx.orgId, deviceId: id }).permissions;
    send(res, 201, row(deviceIn.get(id, ctx.orgId), permissions));
  });

  router.patch('/v1/orgs/:org/devices/:id', (ctx, p, res) => {
    const meta = { action: 'device.update', targetType: 'device', targetId: p.id };
    const { permissions } = visibleDevice(ctx, p.id, meta.action);
    auditDenials(db, ctx, meta, () => assertAllowed(permissions, 'device:update'));

    const name = validName(ctx.body.name);
    db.transaction(() => {
      db.prepare('UPDATE devices SET name = ? WHERE id = ?').run(name, p.id);
      audit(db, { orgId: ctx.orgId, actorId: ctx.userId, requestId: ctx.requestId, ...meta, result: 'allow' });
    })();
    send(res, 200, row(deviceIn.get(p.id, ctx.orgId), permissions));
  });

  // Soft delete. Grants on it go inert (permissions.js skips deleted devices).
  router.delete('/v1/orgs/:org/devices/:id', (ctx, p, res) => {
    const meta = { action: 'device.decommission', targetType: 'device', targetId: p.id };
    const { permissions } = visibleDevice(ctx, p.id, meta.action);
    auditDenials(db, ctx, meta, () => assertAllowed(permissions, 'device:provision'));

    db.transaction(() => {
      db.prepare("UPDATE devices SET deleted_at = strftime('%Y-%m-%dT%H:%M:%fZ','now') WHERE id = ?").run(p.id);
      endActiveSessions(db, { orgId: ctx.orgId, deviceId: p.id, reason: 'device_transferred' });
      audit(db, { orgId: ctx.orgId, actorId: ctx.userId, requestId: ctx.requestId, ...meta, result: 'allow' });
    })();
    send(res, 204);
  });

  // device:provision on the device here AND org-level in the target org.
  router.post('/v1/orgs/:org/devices/:id/transfer', (ctx, p, res) => {
    const meta = { action: 'device.transfer', targetType: 'device', targetId: p.id };
    const { permissions } = visibleDevice(ctx, p.id, meta.action);
    const target = ctx.body.targetOrgId;
    if (typeof target !== 'string') throw badRequest('targetOrgId is required');
    if (target === ctx.orgId) throw badRequest('device is already in that org');

    auditDenials(db, ctx, meta, () => {
      assertAllowed(permissions, 'device:provision');
      if (!activeMember.get(ctx.userId, target)) throw notFound();
      assertAllowed(resolve(db, { userId: ctx.userId, orgId: target }).permissions, 'device:provision');
    });

    db.transaction(() => {
      // Revoke grants on this device, or they would come back to life if it ever
      // returned to this org. Their holders' tokens go stale.
      const holders = db.prepare(
        'SELECT DISTINCT user_id FROM grants WHERE device_id = ? AND org_id = ? AND revoked_at IS NULL'
      ).all(p.id, ctx.orgId);
      db.prepare(
        `UPDATE grants SET revoked_at = strftime('%Y-%m-%dT%H:%M:%fZ','now')
          WHERE device_id = ? AND org_id = ? AND revoked_at IS NULL`
      ).run(p.id, ctx.orgId);
      for (const h of holders) bumpPermVersion(db, { orgId: ctx.orgId, userId: h.user_id });

      endActiveSessions(db, { orgId: ctx.orgId, deviceId: p.id, reason: 'device_transferred' });
      db.prepare('UPDATE devices SET org_id = ? WHERE id = ?').run(target, p.id);
      audit(db, { orgId: ctx.orgId, actorId: ctx.userId, requestId: ctx.requestId, ...meta, result: 'allow' });
    })();
    send(res, 200, { id: p.id, orgId: target });
  });

  // --- grants ------------------------------------------------------------------------

  const listGrants = db.prepare(
    `SELECT g.id, g.user_id AS userId, g.device_id AS deviceId, g.effect,
            g.starts_at AS startsAt, g.expires_at AS expiresAt,
            g.created_by AS createdBy, g.created_at AS createdAt,
            json_group_array(gp.permission) AS permissions
       FROM grants g JOIN grant_permissions gp ON gp.grant_id = g.id
      WHERE g.org_id = ? AND g.revoked_at IS NULL AND (? IS NULL OR g.user_id = ?)
      GROUP BY g.id ORDER BY g.created_at, g.id`
  );
  const liveGrant = db.prepare(
    'SELECT id, user_id FROM grants WHERE id = ? AND org_id = ? AND revoked_at IS NULL'
  );

  // Checks run in the order of AUTH-DATA-MODEL §8. The unknown-permission check is
  // left to the foreign key on grant_permissions, caught below.
  router.post('/v1/orgs/:org/grants', (ctx, _p, res) => {
    const b = ctx.body;
    const meta = { action: 'grant.create', targetType: 'user', targetId: typeof b.userId === 'string' ? b.userId : null };

    const id = auditDenials(db, ctx, meta, () => {
      assertCan(db, ctx, 'grant:create');

      if (!Array.isArray(b.permissions) || b.permissions.length === 0 || !b.permissions.every((x) => typeof x === 'string')) {
        throw badRequest('permissions must be a non-empty array of strings');
      }
      if (b.effect !== 'allow' && b.effect !== 'deny') throw badRequest('effect must be allow or deny');
      if (typeof b.userId !== 'string') throw badRequest('userId is required');
      if (b.deviceId != null && typeof b.deviceId !== 'string') throw badRequest('deviceId must be a string');
      const deviceId = b.deviceId ?? null;
      const startsAt = normalizeTs(b.startsAt, 'startsAt');
      const expiresAt = normalizeTs(b.expiresAt, 'expiresAt');

      if (deviceId !== null && !deviceIn.get(deviceId, ctx.orgId)) throw notFound();
      if (b.userId === ctx.userId) throw forbidden('you cannot grant to yourself', 'self_grant');
      if (!activeMember.get(b.userId, ctx.orgId)) throw notFound();
      if (expiresAt !== null && Date.parse(expiresAt) <= Date.now()) {
        throw new HttpError(400, 'GRANT_EXPIRED', 'expiresAt must be in the future');
      }
      if (startsAt !== null && expiresAt !== null && startsAt >= expiresAt) {
        throw badRequest('expiresAt must be after startsAt');
      }

      const patterns = [...new Set(b.permissions)];
      assertMayGrant(db, ctx, patterns, deviceId);

      const grantId = newId('grt');
      db.transaction(() => {
        db.prepare(
          `INSERT INTO grants (id, org_id, user_id, device_id, effect, starts_at, expires_at, created_by)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?)`
        ).run(grantId, ctx.orgId, b.userId, deviceId, b.effect, startsAt, expiresAt, ctx.userId);
        const addPattern = db.prepare('INSERT INTO grant_permissions (grant_id, permission) VALUES (?, ?)');
        for (const pattern of patterns) {
          try {
            addPattern.run(grantId, pattern);
          } catch (err) {
            // The grant row exists, so the only FK that can fail here is the permission.
            if (err.code === 'SQLITE_CONSTRAINT_FOREIGNKEY') {
              throw badRequest(`unknown permission: ${pattern}`, 'unknown_permission');
            }
            throw err;
          }
        }
        bumpPermVersion(db, { orgId: ctx.orgId, userId: b.userId });
        audit(db, { orgId: ctx.orgId, actorId: ctx.userId, requestId: ctx.requestId, ...meta,
                    targetType: 'grant', targetId: grantId, result: 'allow' });
      })();
      return grantId;
    });

    const grant = listGrants.all(ctx.orgId, b.userId, b.userId).find((g) => g.id === id);
    send(res, 201, { ...grant, permissions: JSON.parse(grant.permissions) });
  });

  router.get('/v1/orgs/:org/grants', (ctx, _p, res) => {
    auditDenials(db, ctx, { action: 'grant.list', targetType: 'org', targetId: ctx.orgId }, () =>
      assertCan(db, ctx, 'user:read'));
    const userId = ctx.query.get('userId');
    const grants = listGrants.all(ctx.orgId, userId, userId).map((g) => ({ ...g, permissions: JSON.parse(g.permissions) }));
    send(res, 200, { grants });
  });

  // Revoking a grant on yourself is refused like a self-grant: dropping your own deny
  // would widen your own authority.
  router.delete('/v1/orgs/:org/grants/:id', (ctx, p, res) => {
    const meta = { action: 'grant.revoke', targetType: 'grant', targetId: p.id };
    const grant = liveGrant.get(p.id, ctx.orgId);
    if (!grant) throw notFound();

    auditDenials(db, ctx, meta, () => {
      assertCan(db, ctx, 'grant:revoke');
      if (grant.user_id === ctx.userId) throw forbidden('you cannot revoke your own grant', 'self_grant');
    });

    db.transaction(() => {
      db.prepare("UPDATE grants SET revoked_at = strftime('%Y-%m-%dT%H:%M:%fZ','now') WHERE id = ?").run(p.id);
      bumpPermVersion(db, { orgId: ctx.orgId, userId: grant.user_id });
      audit(db, { orgId: ctx.orgId, actorId: ctx.userId, requestId: ctx.requestId, ...meta, result: 'allow' });
    })();
    send(res, 204);
  });
}
