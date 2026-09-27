// Auth routes: login, switch org, and "who am I".
//
// All three return the same body, so the console has one shape to read:
//   { token, user, orgId, role, orgs, permissions }
// The refresh cookie is set on login only. POST /auth/refresh is not written yet.

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
    const target = orgId ?? activeOrgs.all(user.id)[0]?.id;
    const membership = target && membershipIn.get(user.id, target);
    if (!membership || membership.status !== 'active') {
      throw unauthenticated('no active membership in that org');
    }

    const refresh = newRefreshToken();
    const expires = new Date(Date.now() + REFRESH_TTL_SECONDS * 1000);
    insertRefresh.run(randomUUID(), user.id, hashRefreshToken(refresh), randomUUID(), expires.toISOString());
    res.setHeader('set-cookie',
      `refresh_token=${refresh}; HttpOnly; Secure; SameSite=Strict; Path=/v1/auth/refresh; Max-Age=${REFRESH_TTL_SECONDS}`);

    send(res, 200, withToken(user.id, target, membership));
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
}
