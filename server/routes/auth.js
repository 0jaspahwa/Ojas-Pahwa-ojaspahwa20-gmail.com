// Auth routes: login, refresh, switch org, and "who am I".
//
// All return the same body, so the console has one shape to read:
//   { token, user, orgId, role, orgs, permissions }   (me: no token)
// The refresh token lives only in an HttpOnly cookie, set by login and refresh.

import { randomUUID } from 'node:crypto';
import {
  issueAccessToken, verifyPassword, hashPassword,
  newRefreshToken, hashRefreshToken, REFRESH_TTL_SECONDS,
} from '../auth.js';
import { resolve } from '../permissions.js';
import { send, badRequest, unauthenticated, notFound, forbidden } from '../http.js';

// Unknown email still pays for one scrypt, so response time does not reveal
// which emails have accounts (BRIEF §5.3: no enumeration oracle).
const DUMMY_HASH = hashPassword(randomUUID());
const BAD_LOGIN = 'wrong email or password';

const refreshCookie = (req) => (req.headers.cookie ?? '').split(';').map((c) => c.trim())
  .find((c) => c.startsWith('refresh_token='))?.slice('refresh_token='.length) || null;

export function registerAuthRoutes(router, { db, secret }) {
  const userByEmail = db.prepare('SELECT id, email, name, password_hash FROM users WHERE email = ?');
  const userById = db.prepare('SELECT id, email, name FROM users WHERE id = ?');

  // Orgs you can switch to. Earliest joined first: that is the default org on login.
  const activeOrgs = db.prepare(
    `SELECT o.id, o.name, o.theme, m.role
       FROM memberships m JOIN organizations o ON o.id = m.org_id
      WHERE m.user_id = ? AND m.status = 'active' AND o.deleted_at IS NULL
      ORDER BY m.joined_at, o.id`
  );
  const membershipIn = db.prepare(
    `SELECT m.role, m.status, m.perm_version
       FROM memberships m JOIN organizations o ON o.id = m.org_id
      WHERE m.user_id = ? AND m.org_id = ? AND o.deleted_at IS NULL`
  );
  const insertRefresh = db.prepare(
    'INSERT INTO refresh_tokens (id, user_id, token_hash, family_id, expires_at) VALUES (?, ?, ?, ?, ?)'
  );
  const refreshByHash = db.prepare(
    'SELECT id, user_id, family_id, expires_at, revoked_at FROM refresh_tokens WHERE token_hash = ?'
  );
  const revokeRefresh = db.prepare(
    "UPDATE refresh_tokens SET revoked_at = strftime('%Y-%m-%dT%H:%M:%fZ','now') WHERE id = ?"
  );
  const revokeFamily = db.prepare(
    `UPDATE refresh_tokens SET revoked_at = strftime('%Y-%m-%dT%H:%M:%fZ','now')
      WHERE family_id = ? AND revoked_at IS NULL`
  );

  // New refresh token in the given family (a new family on login), sent as the cookie.
  function setRefreshCookie(res, userId, familyId = randomUUID()) {
    const raw = newRefreshToken();
    const expires = new Date(Date.now() + REFRESH_TTL_SECONDS * 1000);
    insertRefresh.run(randomUUID(), userId, hashRefreshToken(raw), familyId, expires.toISOString());
    res.setHeader('set-cookie',
      `refresh_token=${raw}; HttpOnly; Secure; SameSite=Strict; Path=/v1/auth/refresh; Max-Age=${REFRESH_TTL_SECONDS}`);
  }

  // The org to issue for: the one asked for, else the earliest joined. Active only.
  function activeMembership(userId, orgId) {
    const target = orgId ?? activeOrgs.all(userId)[0]?.id;
    const membership = target && membershipIn.get(userId, target);
    if (!membership || membership.status !== 'active') throw unauthenticated('no active membership in that org');
    return { target, membership };
  }

  // The shared response. `permissions` is the org-level set; pass it in when the
  // caller already has it, so one request never resolves twice.
  function view(userId, orgId, membership, permissions) {
    return {
      user: userById.get(userId),
      orgId,
      role: membership.role,
      orgs: activeOrgs.all(userId),
      permissions: permissions ?? resolve(db, { userId, orgId }).permissions,
    };
  }

  // A view plus a fresh access token for that org.
  const withToken = (userId, orgId, membership, permissions) => ({
    token: issueAccessToken({ userId, orgId, role: membership.role, permVersion: membership.perm_version }, secret),
    ...view(userId, orgId, membership, permissions),
  });

  router.post('/v1/auth/login', (ctx, _params, res) => {
    const { email, password, orgId } = ctx.body;
    if (typeof email !== 'string' || typeof password !== 'string') {
      throw badRequest('email and password are required');
    }

    const user = userByEmail.get(email.trim().toLowerCase());
    const ok = verifyPassword(password, user?.password_hash ?? DUMMY_HASH);
    if (!user || !ok) throw unauthenticated(BAD_LOGIN);

    // Correct password from here on, so a clearer message leaks nothing.
    const { target, membership } = activeMembership(user.id, orgId);
    setRefreshCookie(res, user.id);
    send(res, 200, withToken(user.id, target, membership));
  });

  // Rotate: the presented token is revoked and a new one issued in the same family.
  // Presenting a token that was already rotated means someone else has a copy, so the
  // whole family is revoked and everyone holding it must log in again.
  // Check-then-rotate cannot interleave: handlers are synchronous in one process.
  router.post('/v1/auth/refresh', (ctx, _p, res) => {
    const raw = refreshCookie(ctx.req);
    if (!raw) throw unauthenticated('missing refresh token');

    const row = refreshByHash.get(hashRefreshToken(raw));
    if (!row) throw unauthenticated('invalid refresh token');
    if (row.revoked_at) {
      revokeFamily.run(row.family_id);
      throw unauthenticated('refresh token reused; signed out');
    }
    if (Date.parse(row.expires_at) <= Date.now()) throw unauthenticated('refresh token expired');

    const orgId = typeof ctx.body.orgId === 'string' ? ctx.body.orgId : undefined;
    const { target, membership } = activeMembership(row.user_id, orgId);
    db.transaction(() => {
      revokeRefresh.run(row.id);
      setRefreshCookie(res, row.user_id, row.family_id);
    })();
    send(res, 200, withToken(row.user_id, target, membership));
  });

  // Sign out: revoke the cookie's whole family and clear the cookie. Lives on the refresh
  // path because the cookie is only sent there (Path=/v1/auth/refresh).
  router.delete('/v1/auth/refresh', (ctx, _p, res) => {
    const row = refreshByHash.get(hashRefreshToken(refreshCookie(ctx.req) ?? ''));
    if (row) revokeFamily.run(row.family_id);
    res.setHeader('set-cookie', 'refresh_token=; HttpOnly; Secure; SameSite=Strict; Path=/v1/auth/refresh; Max-Age=0');
    send(res, 204);
  });

  // Switch org: a new token scoped to another org you are an active member of.
  router.post('/v1/auth/token', (ctx, _params, res) => {
    const { orgId } = ctx.body;
    if (typeof orgId !== 'string') throw badRequest('orgId is required');

    const membership = membershipIn.get(ctx.userId, orgId);
    if (!membership || membership.status === 'removed' || membership.status === 'invited') throw notFound();
    if (membership.status === 'suspended') throw forbidden('suspended in that org', 'suspended');

    send(res, 200, withToken(ctx.userId, orgId, membership, orgId === ctx.orgId ? ctx.permissions : undefined));
  });

  router.get('/v1/auth/me', (ctx, _params, res) => {
    send(res, 200, view(ctx.userId, ctx.orgId, ctx.membership, ctx.permissions));
  });

  // Accepting an invite signs the person in exactly like login does.
  return { withToken, setRefreshCookie };
}
