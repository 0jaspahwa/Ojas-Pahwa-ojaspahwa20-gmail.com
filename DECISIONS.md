# DECISIONS

### File paths come from `fileURLToPath`, not `URL.pathname`

**What I chose:** `fileURLToPath(new URL(p, import.meta.url))` in `scripts/load-db.js` and
`server/index.js`.
**Why:** on Windows, `.pathname` gave `/F:/interview/...` and `db:load` failed with
`ENOENT ... 'F:\F:\interview\rhino\remoteops\db\schema.sql'`. With `fileURLToPath` it loads.
Commit `623de88`. BUILD-LOG, Phase 0.
**What I rejected:** stripping the leading `/` from `.pathname` by hand. It fixes Windows but
breaks Linux and macOS, where the leading `/` is the root. It also leaves `%20` in paths with
spaces. `fileURLToPath` handles both.
**What would change my mind:** nothing on Node. It is the documented way to turn a file URL
into a path on every OS.

---

### The token verifier checks signature length before `timingSafeEqual`

**What I chose:** `actual.length !== expected.length || !timingSafeEqual(...)` in
`verifyAccessToken`, `server/auth.js`.
**Why:** in node, `timingSafeEqual` on 32 vs 6 bytes threw
`RangeError ERR_CRYPTO_TIMING_SAFE_EQUAL_LENGTH`. Without the check, `signature truncated`
in `check-jwt.js` becomes a 500, not a 401. BUILD-LOG, Phase 1.
**What I rejected:** comparing the signatures as strings with `===`. It never throws, but it
stops at the first different character, so response time leaks how much of the signature is
right.
**What would change my mind:** nothing here. Length is not secret: every HS256 signature is
32 bytes, so checking it first leaks nothing.

---

### The header must match exactly; there is no list of banned algorithms

**What I chose:** `header.alg !== 'HS256' || header.typ !== 'JWT'` rejects. The algorithm is
never read from the header. HMAC-SHA256 is always used.
**Why:** `check-jwt.js` rejects `none`, `HS512`, `RS256`, a missing `alg` and a missing `typ`.
Only an exact match covers all five, including ones not in the test.
**What I rejected:** banning `alg: none` only. That passes the three `none` cases but accepts
`HS512`, `RS256` and a missing `alg`.
**What would change my mind:** needing a second algorithm, e.g. RS256 for other services.
Even then I would pin it per key, not read it from the token.

---

### The trace comes from `decide()` itself, not from a second explainer

**What I chose:** `decide()` takes an optional `trace` array. `resolve()` passes `null`,
`explain()` passes an array. One code path makes the decision and the explanation.
**Why:** when I fixed `windowState` (bug 3, BUILD-LOG Phase 2), the fix reached `explain()`
with no extra change. A separate explainer would still compare strings and report a grant
as active that the engine treats as expired.
**What I rejected:** a separate `explain()` that re-walks the grants. It is simpler to read,
but it is a second copy of the rules, and copies drift.
**What would change my mind:** if the "why?" inspector is not built, I delete `explain()` and
the trace. Unused code is not worth defending.

---

### Org-level has two meanings: `'any'` for nav, `'every'` for granting org-wide

**What I chose:** `scopeState(grant, deviceId, orgMode)`. Nav and page gating use `'any'`
(device allows count, device denies do not). `assertMayGrant` uses `'every'` for an org-wide
grant (device denies count, device allows do not).
**Why:** `scripts/probe-engine.js`. With `'any'` everywhere, a viewer holding `device:control`
on one device granted it org-wide: `allowed`, want `refused 403`. With `'every'` everywhere,
4 nav checks fail, including Robin's `device:reboot` at org level.
The shipped suites pass either way, so they could not settle this.
**What I rejected:** one org-level meaning. Each single choice fails one side of the probe.
**What would change my mind:** a test that expects an org-wide grant to be allowed from a
one-device allow. I think it would be laundering, but I would follow the test and argue it here.

---

### Grant windows compare instants, not strings

**What I chose:** `windowState` compares `Date.parse(...)` against `now.getTime()`.
**Why:** a grant with `expires_at = '2030-01-01T09:00:00Z'` was still `allow` at
`09:00:00.000Z`, because `.` sorts before `Z`. That breaks D7. Probe:
`at expiry, written without ms`.
**What I rejected:** keeping string compare and normalising timestamps on write. It only holds
if every writer normalises: the seed, every route, and any test fixture that inserts rows
directly. One miss brings the bug back, silently.
**What would change my mind:** moving the window check into SQL for speed. Then I would
normalise on write and add a `CHECK` on the format, so the database enforces it.

---

## Tools used

- Claude drafted `verifyAccessToken` and the permission engine. Claude's review found the
  3 engine bugs with `scripts/probe-engine.js` and fixed them. I read every change and
  can explain each line.

---

## Where this repo argues with itself

<!-- For each contradiction: quote both statements, say which one you built against, and why. -->

### Suspension bumps `pv`, yet a suspended token should get 403

- AUTH-DATA-MODEL §1: `pv` "goes up whenever something authorization-relevant changes: ...
  a suspension, a removal."
- AUTH-DATA-MODEL §10: "a token for a suspended membership → `403` with an empty permission set".

If both hold and freshness is checked first, every suspended token is stale, so the answer is
always `401 TOKEN_STALE`. The §10 `403` can never happen.

**Built against:** both. Suspension still bumps `pv`, and `server/context.js` skips the
freshness check for a suspended member only. The caller is built with zero allows, so routes
return `403` with reason `suspended`.
**Why this is safe:** freshness exists so a stale token cannot carry old authority. A suspended
member has no authority to carry: every permission is `deny`, reason `suspended`.
Probe: `suspended (pv bumped): caller still built ... with zero allows` in
`scripts/probe-context.js`.
**Why not the other way:** not bumping `pv` on suspension breaks §1 and leaves every other
token check to catch it. Letting 401 win makes §10 dead text, and the client would try to
refresh a token for a membership that cannot be refreshed into anything useful.

### "Suspended user has no permissions anywhere", but suspension is per org

- PERMISSIONS §3, step 1: "A deleted or suspended user has no permissions anywhere."
- BRIEF §5.1: suspension is `POST /v1/orgs/{org}/members/{userId}/suspend`, one membership.
  AUTH-DATA-MODEL D16 and PERMISSIONS §9.13 ("ends their live sessions **in that org**")
  agree it is per org.
- `db/schema.sql`: "Users are NEVER deleted (D15)". There is no deleted user to handle.

**Built against:** per-org. Suspension lives on `memberships.status`. `users` has no status
column to hold an "anywhere" suspension.
**Evidence:** probe `...Sam in Globex is untouched`: Sam suspended in Acme is still `auditor`
in Globex.
**Why not "anywhere":** it needs a user-level status the schema does not have, and one org's
admin would lock a person out of orgs that admin cannot see. That is a cross-org effect,
exactly what AUTH-DATA-MODEL §4 forbids.

## Deliberately not built

<!-- What you chose not to build, and why. -->
