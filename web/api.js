// The API client.
//
// The access token lives in this module's memory and nowhere else (D13): not in
// localStorage, not in sessionStorage, not in a readable cookie. A reload loses it, and
// POST /auth/refresh (the httpOnly cookie) gets a new one.

let token = null;
let orgId = null;
let listener = () => {};
let refreshing = null;

export class ApiError extends Error {
  constructor(status, body) {
    const e = body?.error ?? {};
    super(e.message ?? `The server answered ${status} with no explanation.`);
    this.status = status;
    this.code = e.code ?? `HTTP_${status}`;
    this.reason = e.reason ?? null;
  }
}

// The app registers one listener; it hears every new session (or null: signed out).
export function onSession(fn) { listener = fn; }

export function applySession(session) {
  token = session?.token ?? null;
  orgId = session?.orgId ?? null;
  listener(session);
}

// One request, no retry. Used directly for the public routes (login, invites).
export async function call(method, path, body) {
  let res;
  try {
    res = await fetch(`/v1${path}`, {
      method,
      headers: {
        ...(token ? { authorization: `Bearer ${token}` } : {}),
        ...(body ? { 'content-type': 'application/json' } : {}),
      },
      body: body ? JSON.stringify(body) : undefined,
    });
  } catch {
    throw new ApiError(0, { error: { code: 'NETWORK', message: 'The server is not answering. Is it running?' } });
  }
  const text = await res.text();
  let json = null;
  try { json = text ? JSON.parse(text) : null; } catch { /* not JSON: handled below */ }
  if (!res.ok) throw new ApiError(res.status, json);
  return json;
}

// One refresh at a time. Two refreshes with the same cookie look like a replay to the
// server, which then revokes the whole family and signs this tab out.
export function refresh(wantOrgId) {
  refreshing ??= call('POST', '/auth/refresh', wantOrgId ? { orgId: wantOrgId } : undefined)
    .then((s) => { applySession(s); return s; })
    .catch((err) => { applySession(null); throw err; })
    .finally(() => { refreshing = null; });
  return refreshing;
}

// An authenticated request. A 401 (stale or expired token) gets one refresh into the
// same org and one retry; the new session also updates the nav.
export async function api(method, path, body) {
  try {
    return await call(method, path, body);
  } catch (err) {
    if (err.status !== 401 || !token) throw err;
    await refresh(orgId);
    return call(method, path, body);
  }
}

export async function signOut() {
  try { await call('DELETE', '/auth/refresh'); } finally { applySession(null); }
}
