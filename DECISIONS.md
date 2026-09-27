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
in `check-jwt.js` becomes a 500, not a 401. BUILD-LOG, Phase 1. Commit `0c50d3a`.
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
Only an exact match covers all five, including ones not in the test. Commit `0c50d3a`.
**What I rejected:** banning `alg: none` only. That passes the three `none` cases but accepts
`HS512`, `RS256` and a missing `alg`.
**What would change my mind:** needing a second algorithm, e.g. RS256 for other services.
Even then I would pin it per key, not read it from the token.

---

### Trace comes from `decide()`, not a second explainer

**What I chose:** `decide()` takes an optional `trace` array. `resolve()` passes `null`,
`explain()` passes an array. One code path makes the decision and the explanation.
Only `GET /users/:id/explain` builds a trace; normal requests never do.
**Why:** `scripts/probe-explain.js` compares `explain().decision` with
`resolve().permissions[p]` for every membership x permission x device (and org level), in
all three orgs incl. the personalised one: **900 checked, 900 agree**. It reaches every
trace branch (active, suspended, not a member; expired, not started, other device).
Broken on purpose (explain skipped deny grants): **35 of 900 disagree**, every one a case a
deny decides. Also: the `windowState` fix (bug 3, Phase 2) reached `explain()` for free.
**What I rejected:** a separate `explain()` that re-walks the grants. It reads more simply,
but it is a second copy of the rules. The probe shows how fast a copy goes wrong: one
skipped step, 35 wrong answers, and nothing else in the suites would notice.
**What would change my mind:** if tracing slowed normal requests. It cannot today: every
trace line is behind `if (trace)`, and `resolve()` passes `null`.

---

### Org-level has two meanings: `'any'` for nav, `'every'` for granting org-wide

**What I chose:** `scopeState(grant, deviceId, orgMode)`. Nav and page gating use `'any'`
(device allows count, device denies do not). `assertMayGrant` uses `'every'` for an org-wide
grant (device denies count, device allows do not).
**Why:** `scripts/probe-engine.js`. With `'any'` everywhere, a viewer holding `device:control`
on one device granted it org-wide: `allowed`, want `refused 403`. With `'every'` everywhere,
4 nav checks fail, including Robin's `device:reboot` at org level.
The shipped suites pass either way, so they could not settle this. Commit `57b3cb9`.
**What I rejected:** one org-level meaning. Each single choice fails one side of the probe.
**What would change my mind:** a test that expects an org-wide grant to be allowed from a
one-device allow. I think it would be laundering, but I would follow the test and argue it here.

---

### Grant windows compare instants, not strings

**What I chose:** `windowState` compares `Date.parse(...)` against `now.getTime()`.
**Why:** a grant with `expires_at = '2030-01-01T09:00:00Z'` was still `allow` at
`09:00:00.000Z`, because `.` sorts before `Z`. That breaks D7. Probe:
`at expiry, written without ms`. Commit `57b3cb9`.
**What I rejected:** keeping string compare and normalising timestamps on write. It only holds
if every writer normalises: the seed, every route, and any test fixture that inserts rows
directly. One miss brings the bug back, silently.
**What would change my mind:** moving the window check into SQL for speed. Then I would
normalise on write and add a `CHECK` on the format, so the database enforces it.

---

### Login without `orgId` lands in the org you joined first

**What I chose:** the active membership with the earliest `joined_at` (tie: org id).
Same order is used for the `orgs` list in the login, switch and `/auth/me` responses.
**Why:** no document says. Dana and Sam both joined Acme first, and `check-api.js`
(`dana is owner in Acme`) and `tests/ui.spec.js` (`sam ... operator in Acme`) expect Acme.
Commit `223e811`; probe `no orgId: earliest joined (Acme, owner)` in `probe-auth.js`.
**What I rejected:** alphabetical by org name. It passes the same tests (Acme < Globex) but
depends on names, which admins can rename, so the default org could change under a user.
Also "most recently used": it needs state the schema does not store.
**What would change my mind:** a test that logs in a user whose first-joined org sorts after
another by name, and expects the other one.

---

### A device you cannot `device:view` is a 404, also on its own endpoint

**What I chose:** `visibleDevice` in `server/routes/devices.js`: missing, deleted, other org, or
no `device:view` are all `404` with the same body. The attempt is still audited (`not_visible`).
**Why:** the list already hides the row (`kiosk-lobby-01 is ABSENT` in `check-api.js`). A 403 on
`GET /devices/:id` would confirm the id exists. Probe `...same body as a device that does not
exist` in `probe-routes.js`. Commit `7cf396c`.
**What I rejected:** 403, the PERMISSIONS §5 default for "visible but not permitted". It fits
other permissions, but `device:view` *is* the visibility permission.
**What would change my mind:** a test that expects 403 there. The list and the endpoint would
then disagree about whether the device exists, and I would argue it here.

---

### Member changes run in IMMEDIATE transactions, for the error code, not the data

**What I chose:** `.immediate()` on role change, suspend, reinstate, remove, leave and accept.
**Why:** measured with two server processes (`probe-members.js`). With IMMEDIATE: every round
one winner and a clean 409. Without it, the data was still right (WAL rejects the loser), but
1 accept round in 5 returned `500 SQLITE_BUSY_SNAPSHOT`. Commits `409b2f4`, `101ffbb`.
**What I rejected:** a plain transaction. I believed it allowed a double win; the experiment
showed it only gives the loser the wrong status. My first code comment said the wrong thing.
**What would change my mind:** running more than one writer against a server database (not
SQLite). Then this becomes a row lock or a serializable transaction.

---

### Accepting an invite for an existing account attaches it; only a password signs in

**What I chose:** existing account, no password: membership attached, `200`, no token, no
cookie. Right password: attached and signed in. Wrong password: `401`, nothing attached.
**Why:** probe lines `existing user, no password -> 200, attached` and `...but not signed in:
no token, no cookie` in `probe-members.js`. Commit `951c9ce`.
**What I rejected:** my first version (`409b2f4`): password required, else 401. Safe, but it
blocked a person who owns the email and only wants the membership. Also rejected: issuing
tokens on the token alone. A forwarded invite link would then sign someone in to another
person's account.
**What would change my mind:** invites sent to addresses the org does not control. Then attach
should need the password too.

---

## Tools used

- Built with Claude (Anthropic), in pairing sessions: Claude wrote the code, the probes and
  drafts of these notes to my step-by-step specs. Every line was reviewed, probed and
  understood by me before it was committed. Claude's probes found the 3 engine bugs
  (`probe-engine.js`) and the TTL clock bug (`probe-sessions.js`).
- Libraries: only those the starter ships (`better-sqlite3`, React, Vite, Playwright). No code
  was copied from any other repository, blog post or solution.

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

### "Flip the membership from `invited` to `active`" needs a user that does not exist yet

- AUTH-DATA-MODEL §6: accept will "upsert the user, flip the membership from `invited` to
  `active`".
- `db/schema.sql`: `memberships.user_id TEXT NOT NULL REFERENCES users(id)`.

A person invited by email has no `users` row, so there is no `invited` membership to flip.
**Built against:** the schema. The membership is created on accept, or an old `removed`
row is reactivated. `invited` status is never written. `server/routes/invites.js`.

### The unique index does not make accept single-use

- AUTH-DATA-MODEL §6: "Two concurrent accepts of the same token: exactly one wins. The partial
  unique index `one_live_invite_per_email` makes that a database guarantee."
- The index is on `(org_id, email) WHERE accepted_at IS NULL AND revoked_at IS NULL`. It stops
  two live invites. It says nothing about accepting one invite twice.

**Built against:** the behaviour, not the stated mechanism. Accept re-reads the invite inside
an IMMEDIATE transaction. Probe: `5 rounds of two parallel accepts: one 200, one 409`, two
server processes.

### Equal role is 403, but owners must demote owners

- PERMISSIONS §6: "modify a user of equal role (admin → admin) | `403`".
- `check-api.js`: `demoting a NON-last owner is allowed` (owner demotes owner, 200).

**Built against:** both. Equal role is 403, except for the top role. Without the exception a
co-owner could never be demoted, and the last-owner rule already guards the danger.
`assertCanModify` in `server/lifecycle.js`. Probe: `admin -> admin (equal, not top) -> 403`.

### "`device:*` collapses to the seven device permissions; `*` to all nineteen"

- PERMISSIONS §4 (and §2: "five rows", "the nineteen permissions").
- The database: 6 roles and 20 permissions, 8 of them `device:`. The personalised overlay adds
  `reviewer` and `device:reboot` (README: "the prose ... is not the model: the database is").

**Built against:** the database. `patternMatches` in `server/permissions.js` matches `device:*` by
prefix against the `permissions` table, so it covers `device:reboot` too. No count is written
anywhere. Evidence: `probe-explain.js` runs over 20 permissions, 900/900.

### "Plain string comparison works" for timestamps, until two writers disagree on format

- `server/db.js`: "lexicographic order == chronological order and plain string comparison works".
- `server/http.js` `normalizeTs`: '+' sorts before 'Z', so '...+00:00' is "silently mis-ordered".
  The same happens with '...:00Z' vs '...:00.000Z' ('.' sorts before 'Z').

**Built against:** instants. `windowState` compares `Date.parse` numbers. Probe
`at expiry, written without ms` in `probe-engine.js`. See the decision above.

### Invite tokens: `sha256(token)` or HMAC?

- AUTH-DATA-MODEL §6: "stores `sha256(token)`".
- `server/auth.js` (given): `hashInviteToken` is HMAC-SHA256 with `APP_HASH_KEY`.

**Built against:** the given code. A keyed hash cannot be checked offline by someone who only
reads the database. Probe: `token stored hashed`.

## Deliberately not built

- **File transfer.** `transfer-files` is present per permission, but only shows a notice: there
  is no device agent to move files to. Out of scope for a permission console.
- **Email.** No invite is emailed; the raw token comes back once in the `POST /invites`
  response and the console shows the link. BRIEF lists email delivery as not here.
- **Pagination and search** on lists. Only `GET /audit` pages (`limit`/`offset`, strict). The
  fixture is small; sessions cap at 500 rows.
- **Rate limiting.** BRIEF lists it as not here. Login does pay a full scrypt either way.
- **Two-tab refresh race.** Two tabs refreshing at once: the second looks like a replay and
  signs the user out. Fix would be a short grace window for the just-rotated token.
- **Transfer is audited in the old org only.** One action, one row. The new org's log does not
  show the device arriving.
- **`GET /grants` shows device ids** for devices the reader cannot view. The console never
  names them, but the API returns the id.
- **`device:provision` on one device lets you create devices** (`POST /devices` checks the
  org-level union). Should use `'every'`, like org-wide grants.
