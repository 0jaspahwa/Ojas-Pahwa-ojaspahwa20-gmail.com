// Devices and grants.
//
// Visibility first, permission second: a device that is missing, deleted, in another
// org, or that you cannot device:view is a 404. Only a device you can see gets a 403.

import { resolve, resolveDevices, assertCan, assertAllowed, assertMayGrant } from '../permissions.js';
import { audit, auditDenials } from '../audit.js';
import { endActiveSessions } from '../lifecycle.js';
import { newId, bumpPermVersion } from '../db.js';
import { send, badRequest, notFound } from '../http.js';

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
}
