// Invites: the only way to add a person (D14).
//
// The raw token is returned once, stored hashed, and is single-use. Accept runs in an
// IMMEDIATE transaction and re-reads the invite inside it: the second of two parallel
// accepts waits for the lock, sees the invite used, and gets 409 rather than a 500
// SQLITE_BUSY_SNAPSHOT (measured: scripts/probe-members.js).

import { assertCan } from '../permissions.js';
import { audit, auditDenials } from '../audit.js';
import { assertRoleExists, assertCanAssign } from '../lifecycle.js';
import { newInviteToken, hashInviteToken, hashPassword, verifyPassword } from '../auth.js';
import { newId, bumpPermVersion } from '../db.js';
import { send, badRequest, unauthenticated, notFound, conflict, gone } from '../http.js';

const INVITE_TTL_MS = 7 * 24 * 60 * 60 * 1000;
const EMAIL = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
const NOW = "strftime('%Y-%m-%dT%H:%M:%fZ','now')";

function normalEmail(value) {
  const email = typeof value === 'string' ? value.trim().toLowerCase() : '';
  if (!EMAIL.test(email) || email.length > 254) throw badRequest('a valid email is required');
  return email;
}

export function registerInviteRoutes(router, { db }, { withToken, setRefreshCookie }) {
  const inviteByHash = db.prepare(
    `SELECT i.id, i.org_id, i.email, i.role, i.invited_by, i.expires_at, i.accepted_at, i.revoked_at,
            o.name AS org_name, o.deleted_at AS org_deleted
       FROM invites i JOIN organizations o ON o.id = i.org_id
      WHERE i.token_hash = ?`
  );
  const userByEmail = db.prepare('SELECT id, password_hash FROM users WHERE email = ?');
  const membershipOf = db.prepare('SELECT role, status, perm_version FROM memberships WHERE org_id = ? AND user_id = ?');

  // Unknown -> 404, accepted -> 409, revoked or expired -> 410 (AUTH-DATA-MODEL §6).
  function liveInvite(token) {
    const inv = inviteByHash.get(hashInviteToken(token));
    if (!inv || inv.org_deleted) throw notFound();
    if (inv.accepted_at) throw conflict('invite already used');
    if (inv.revoked_at || Date.parse(inv.expires_at) <= Date.now()) throw gone();
    return inv;
  }

  router.post('/v1/orgs/:org/invites', (ctx, _p, res) => {
    const meta = { action: 'invite.create', targetType: 'org', targetId: ctx.orgId };
    const role = ctx.body.role;
    auditDenials(db, ctx, meta, () => {
      assertCan(db, ctx, 'user:invite');
      assertRoleExists(db, role);
      assertCanAssign(db, ctx.role, role);
    });
    const email = normalEmail(ctx.body.email);

    const already = db.prepare(
      `SELECT 1 FROM memberships m JOIN users u ON u.id = m.user_id
        WHERE m.org_id = ? AND u.email = ? AND m.status IN ('active', 'suspended')`
    ).get(ctx.orgId, email);
    if (already) throw conflict('already a member');

    const token = newInviteToken();
    const id = newId('inv');
    const expiresAt = new Date(Date.now() + INVITE_TTL_MS).toISOString();
    try {
      db.transaction(() => {
        // An expired invite still counts as "live" for the unique index (it only looks at
        // accepted_at and revoked_at). Retire it, or that email could never be invited again.
        db.prepare(
          `UPDATE invites SET revoked_at = ${NOW}
            WHERE org_id = ? AND email = ? AND accepted_at IS NULL AND revoked_at IS NULL AND expires_at <= ${NOW}`
        ).run(ctx.orgId, email);
        db.prepare(
          `INSERT INTO invites (id, org_id, email, role, token_hash, invited_by, expires_at)
           VALUES (?, ?, ?, ?, ?, ?, ?)`
        ).run(id, ctx.orgId, email, role, hashInviteToken(token), ctx.userId, expiresAt);
        audit(db, { orgId: ctx.orgId, actorId: ctx.userId, requestId: ctx.requestId, ...meta,
                    targetType: 'invite', targetId: id, result: 'allow' });
      })();
    } catch (err) {
      // one_live_invite_per_email: the database refuses a second live invite.
      if (err.code === 'SQLITE_CONSTRAINT_UNIQUE') throw conflict('a live invite already exists for that email');
      throw err;
    }
    send(res, 201, { id, email, role, expiresAt, inviteToken: token });
  });

  router.get('/v1/orgs/:org/invites', (ctx, _p, res) => {
    auditDenials(db, ctx, { action: 'invite.list', targetType: 'org', targetId: ctx.orgId }, () =>
      assertCan(db, ctx, 'user:invite'));
    const invites = db.prepare(
      `SELECT id, email, role, invited_by AS invitedBy, expires_at AS expiresAt, created_at AS createdAt
         FROM invites
        WHERE org_id = ? AND accepted_at IS NULL AND revoked_at IS NULL AND expires_at > ${NOW}
        ORDER BY created_at DESC`
    ).all(ctx.orgId);
    send(res, 200, { invites });
  });

  router.delete('/v1/orgs/:org/invites/:id', (ctx, p, res) => {
    const meta = { action: 'invite.revoke', targetType: 'invite', targetId: p.id };
    auditDenials(db, ctx, meta, () => assertCan(db, ctx, 'user:invite'));
    db.transaction(() => {
      const changed = db.prepare(
        `UPDATE invites SET revoked_at = ${NOW}
          WHERE id = ? AND org_id = ? AND accepted_at IS NULL AND revoked_at IS NULL`
      ).run(p.id, ctx.orgId).changes;
      if (!changed) throw notFound();
      audit(db, { orgId: ctx.orgId, actorId: ctx.userId, requestId: ctx.requestId, ...meta, result: 'allow' });
    })();
    send(res, 204);
  });

  // Public. Only enough to render "You've been invited to X as Y."
  router.get('/v1/invites/:token', (_ctx, p, res) => {
    const inv = liveInvite(p.token);
    send(res, 200, { orgName: inv.org_name, role: inv.role, email: inv.email, expiresAt: inv.expires_at });
  });

  // Public. A new person sets name and password. An existing user must prove it is them
  // with their current password: the token alone must not sign in to someone's account.
  router.post('/v1/invites/:token/accept', (ctx, p, res) => {
    const inv = liveInvite(p.token);
    const existing = userByEmail.get(inv.email);
    const { name, password } = ctx.body;
    if (typeof password !== 'string') throw badRequest('password is required');
    if (existing) {
      if (!verifyPassword(password, existing.password_hash)) throw unauthenticated('wrong password for this account');
    } else {
      if (typeof name !== 'string' || !name.trim() || name.trim().length > 100) throw badRequest('name must be 1-100 characters');
      if (password.length < 8) throw badRequest('password must be at least 8 characters');
    }
    const passwordHash = existing ? null : hashPassword(password);

    const userId = existing?.id ?? newId('usr');
    db.transaction(() => {
      // Re-read under the write lock: another process may have accepted it meanwhile.
      liveInvite(p.token);
      if (!existing) {
        db.prepare('INSERT INTO users (id, email, name, password_hash) VALUES (?, ?, ?, ?)')
          .run(userId, inv.email, name.trim(), passwordHash);
      }
      const m = membershipOf.get(inv.org_id, userId);
      if (m && (m.status === 'active' || m.status === 'suspended')) throw conflict('already a member');
      if (m) {
        db.prepare(
          `UPDATE memberships SET role = ?, status = 'active', invited_by = ?, joined_at = ${NOW}
            WHERE org_id = ? AND user_id = ?`
        ).run(inv.role, inv.invited_by, inv.org_id, userId);
        bumpPermVersion(db, { orgId: inv.org_id, userId });
      } else {
        db.prepare(
          `INSERT INTO memberships (id, org_id, user_id, role, status, invited_by, joined_at)
           VALUES (?, ?, ?, ?, 'active', ?, ${NOW})`
        ).run(newId('mem'), inv.org_id, userId, inv.role, inv.invited_by);
      }
      db.prepare(`UPDATE invites SET accepted_at = ${NOW}, accepted_by = ? WHERE id = ?`).run(userId, inv.id);
      audit(db, { orgId: inv.org_id, actorId: userId, action: 'invite.accept', targetType: 'invite',
                  targetId: inv.id, result: 'allow', requestId: ctx.requestId });
    }).immediate();

    setRefreshCookie(res, userId);
    send(res, 200, withToken(userId, inv.org_id, membershipOf.get(inv.org_id, userId)));
  });
}
