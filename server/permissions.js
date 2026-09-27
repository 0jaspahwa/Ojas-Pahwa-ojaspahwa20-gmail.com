// The permission resolution engine. THE ONLY PLACE allow-vs-deny is decided.
//
// Everything is read from the database: the catalogue, the role baselines and the
// grants. Nothing about the documented 19 permissions or 5 roles is written here.
//
// The same code path produces the answer AND (when asked) the trace that explains it,
// so the "why?" inspector can never disagree with the real decision.

import { forbidden } from './http.js';

export const MODE_PERMISSION = { view: 'device:view', control: 'device:control', terminal: 'device:terminal' };

// --- loading --------------------------------------------------------------------

function loadCatalogue(db) {
  return db.prepare('SELECT key FROM permissions ORDER BY key').all().map((r) => r.key);
}

function loadMembership(db, userId, orgId) {
  return db.prepare('SELECT role, status FROM memberships WHERE user_id = ? AND org_id = ?').get(userId, orgId);
}

function loadBaseline(db, role) {
  return new Set(db.prepare('SELECT permission FROM role_permissions WHERE role = ?').all(role).map((r) => r.permission));
}

// Every non-revoked grant for this user in this org, with its patterns. One query.
// Grants on a deleted device are dropped: that device no longer exists.
// Grants on a device that has moved to another org are dropped too.
function loadGrants(db, userId, orgId) {
  const rows = db.prepare(
    `SELECT g.id, g.device_id, g.effect, g.starts_at, g.expires_at, gp.permission AS pattern
       FROM grants g
       JOIN grant_permissions gp ON gp.grant_id = g.id
       LEFT JOIN devices d ON d.id = g.device_id
      WHERE g.user_id = ? AND g.org_id = ? AND g.revoked_at IS NULL
        AND (g.device_id IS NULL OR (d.deleted_at IS NULL AND d.org_id = g.org_id))
      ORDER BY g.id`
  ).all(userId, orgId);

  const byId = new Map();
  for (const r of rows) {
    if (!byId.has(r.id)) {
      byId.set(r.id, { id: r.id, deviceId: r.device_id, effect: r.effect,
                       startsAt: r.starts_at, expiresAt: r.expires_at, patterns: [] });
    }
    byId.get(r.id).patterns.push(r.pattern);
  }
  return [...byId.values()];
}

// --- small rules ------------------------------------------------------------------

// '*' matches everything; 'device:*' matches anything starting with 'device:'.
function patternMatches(pattern, permission) {
  if (pattern === '*') return true;
  if (pattern.endsWith(':*')) return permission.startsWith(pattern.slice(0, -1));
  return pattern === permission;
}

// Half-open window: starts_at <= now < expires_at.
// Compared as instants, not strings: '...:00Z' and '...:00.000Z' are the same time but
// sort differently as text. Routes reject bad timestamps with 400, so 'invalid' only
// happens if something bypasses them; such a grant is ignored.
const toMs = (s) => (s == null ? null : Date.parse(s));
function windowState(grant, nowMs) {
  const start = toMs(grant.startsAt);
  const end = toMs(grant.expiresAt);
  if (Number.isNaN(start) || Number.isNaN(end)) return 'invalid';
  if (start !== null && nowMs < start) return 'not_started';
  if (end !== null && nowMs >= end) return 'expired';
  return 'active';
}

// Device-level: org-wide grants plus grants on exactly this device.
// Org-level (deviceId null) has two meanings:
//   'any'   - held on at least one device (the union). Used for nav and page gating.
//             Device-scoped allows count; device-scoped denies do not.
//   'every' - held on every device. Used to check an org-wide grant for laundering.
//             Device-scoped denies count; device-scoped allows do not.
function scopeState(grant, deviceId, orgMode) {
  if (grant.deviceId === null) return 'in_scope';
  if (deviceId === null) {
    const counts = orgMode === 'every' ? grant.effect === 'deny' : grant.effect === 'allow';
    return counts ? 'in_scope' : 'other_device';
  }
  return grant.deviceId === deviceId ? 'in_scope' : 'other_device';
}

const allow = (source) => ({ effect: 'allow', source, reason: null });
const deny = (source, reason) => ({ effect: 'deny', source, reason });

// --- the one decision function ---------------------------------------------------------

// Decide one permission. If `trace` is an array, every step is pushed into it.
function decide(permission, { role, baseline, grants, deviceId, nowMs, orgMode = 'any' }, trace) {
  const considered = [];
  const denies = [];
  const allows = [];

  for (const g of grants) {
    const pattern = g.patterns.find((p) => patternMatches(p, permission));
    if (!pattern) continue;

    const window = windowState(g, nowMs);
    const scope = scopeState(g, deviceId, orgMode);
    const applies = window === 'active' && scope === 'in_scope';

    if (trace) {
      considered.push({ grant: g.id, effect: g.effect, pattern, deviceId: g.deviceId,
                        window, scope, applies });
    }
    if (applies) (g.effect === 'deny' ? denies : allows).push(g);
  }

  if (trace) trace.push({ step: 'grants', considered });

  // Deny wins, whatever the scope.
  if (denies.length) {
    if (trace) trace.push({ step: 'deny_wins', grant: denies[0].id });
    return deny(`grant:${denies[0].id}`, 'explicit_deny');
  }

  if (baseline.has(permission)) {
    if (trace) trace.push({ step: 'baseline', result: `role ${role} contains ${permission}` });
    return allow(`role:${role}`);
  }
  if (trace) trace.push({ step: 'baseline', result: `role ${role} does not contain ${permission}` });

  if (allows.length) {
    if (trace) trace.push({ step: 'allow_grant', grant: allows[0].id });
    return allow(`grant:${allows[0].id}`);
  }

  if (trace) trace.push({ step: 'implicit_deny' });
  return deny(null, 'implicit');
}

// Load everything one (user, org) needs. Shared by resolve() and resolveDevices()
// so a list endpoint loads once, not once per device.
function loadInputs(db, userId, orgId) {
  const catalogue = loadCatalogue(db);
  const membership = loadMembership(db, userId, orgId);

  if (!membership || membership.status === 'removed' || membership.status === 'invited') {
    return { catalogue, role: null, blocked: 'not_a_member' };
  }
  if (membership.status === 'suspended') {
    return { catalogue, role: membership.role, blocked: 'suspended' };
  }
  return {
    catalogue,
    role: membership.role,
    blocked: null,
    baseline: loadBaseline(db, membership.role),
    grants: loadGrants(db, userId, orgId),
  };
}

function resolveWith(inputs, deviceId, nowMs, orgMode = 'any') {
  const permissions = {};
  for (const p of inputs.catalogue) {
    permissions[p] = inputs.blocked
      ? deny(null, inputs.blocked)
      : decide(p, { ...inputs, deviceId, nowMs, orgMode }, null);
  }
  return { role: inputs.role, permissions };
}

// --- public API --------------------------------------------------------------------

// Resolve one user's permission set in one org. deviceId === null means the org-level
// view; a deviceId means the exact per-device check.
export function resolve(db, { userId, orgId, deviceId = null, now = new Date() }) {
  return resolveWith(loadInputs(db, userId, orgId), deviceId, now.getTime());
}

// Batched form for list endpoints: { role, byDevice: { [deviceId]: permissions } }.
export function resolveDevices(db, { userId, orgId, deviceIds, now = new Date() }) {
  const inputs = loadInputs(db, userId, orgId);
  const nowMs = now.getTime();
  const byDevice = {};
  for (const id of deviceIds) byDevice[id] = resolveWith(inputs, id, nowMs).permissions;
  return { role: inputs.role, byDevice };
}

// The "why?" inspector. Same decide() as above, with the trace switched on.
export function explain(db, { userId, orgId, permission, deviceId = null, now = new Date() }) {
  const inputs = loadInputs(db, userId, orgId);
  const trace = [{ step: 'membership', role: inputs.role, result: inputs.blocked ?? 'active' }];

  if (!inputs.catalogue.includes(permission)) {
    return { permission, deviceId, decision: deny(null, 'unknown_permission'), trace };
  }
  const decision = inputs.blocked
    ? deny(null, inputs.blocked)
    : decide(permission, { ...inputs, deviceId, nowMs: now.getTime() }, trace);

  return { permission, deviceId, decision, trace };
}

// Exact check for one permission. ctx needs { userId, orgId }.
// An org-level question reuses ctx.permissions when context.js already resolved them,
// so one request does not resolve the same set twice.
export function check(db, ctx, permission, deviceId = null) {
  const set = deviceId === null && ctx.permissions
    ? ctx.permissions
    : resolve(db, { userId: ctx.userId, orgId: ctx.orgId, deviceId }).permissions;
  return set[permission] ?? deny(null, 'unknown_permission');
}

export function can(db, ctx, permission, deviceId = null) {
  return check(db, ctx, permission, deviceId).effect === 'allow';
}

// Throws 403 carrying the reason code, so a refusal is debuggable.
export function assertCan(db, ctx, permission, deviceId = null) {
  const r = check(db, ctx, permission, deviceId);
  if (r.effect === 'allow') return r;
  const reason = r.reason === 'implicit' ? 'missing_permission' : r.reason;
  throw forbidden(`missing ${permission}`, reason);
}

// No privilege laundering: you may only grant authority you hold at that scope.
// A wildcard is expanded to every concrete permission it covers, and each is checked.
// An org-wide grant covers every device, so the granter must hold it on every device.
export function assertMayGrant(db, ctx, patterns, deviceId = null) {
  const inputs = loadInputs(db, ctx.userId, ctx.orgId);
  const held = resolveWith(inputs, deviceId, Date.now(), 'every').permissions;
  for (const pattern of patterns) {
    for (const p of Object.keys(held)) {
      if (patternMatches(pattern, p) && held[p].effect !== 'allow') {
        throw forbidden(`you cannot grant ${p} because you do not hold it`, 'missing_permission');
      }
    }
  }
}

// The compound check: session:start AND the permission for the requested mode, on the
// same device. The reason says WHICH of the two was missing.
export function assertCanStartSession(db, ctx, mode, deviceId) {
  const needed = MODE_PERMISSION[mode];
  const set = resolve(db, { userId: ctx.userId, orgId: ctx.orgId, deviceId }).permissions;

  if (set['session:start']?.effect !== 'allow') {
    throw forbidden('missing session:start on this device', 'missing_permission');
  }
  if (set[needed]?.effect !== 'allow') {
    throw forbidden(`missing ${needed} on this device`, 'missing_device_permission');
  }
  return set;
}
