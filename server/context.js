// Per-request context: turn a bearer token into an authenticated caller.
//
// Order: token -> membership -> freshness -> org in the path -> permissions.
// The token's org claim is the only org the caller may address. Any other org in the
// path is a 404, the same as an org that does not exist.

import { verifyAccessToken, assertFresh } from './auth.js';
import { resolve } from './permissions.js';
import { unauthenticated, notFound } from './http.js';

const BEARER = /^Bearer\s+(\S+)$/i;

export function authenticate(db, secret) {
  const loadMembership = db.prepare(
    `SELECT m.id, m.role, m.status, m.perm_version
       FROM memberships m
       JOIN organizations o ON o.id = m.org_id
      WHERE m.user_id = ? AND m.org_id = ? AND o.deleted_at IS NULL`
  );

  return function buildContext(req, params) {
    const match = BEARER.exec(req.headers.authorization ?? '');
    if (!match) throw unauthenticated('missing bearer token');
    const claims = verifyAccessToken(match[1], secret);

    const membership = loadMembership.get(claims.sub, claims.org);
    if (!membership || membership.status === 'removed' || membership.status === 'invited') {
      throw unauthenticated('not a member of this org');
    }

    // Suspension bumps pv (AUTH-DATA-MODEL §1), so a freshness check here would turn
    // every suspended caller into 401 TOKEN_STALE and §10's 403 could never happen.
    // Skipping it is safe: resolve() gives a suspended member no permissions at all.
    if (membership.status !== 'suspended') assertFresh(claims, membership);

    if (params.org !== undefined && params.org !== claims.org) throw notFound();

    const { role, permissions } = resolve(db, { userId: claims.sub, orgId: claims.org });
    return { userId: claims.sub, orgId: claims.org, role, membership, claims, permissions };
  };
}
