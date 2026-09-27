# BUILD-LOG

## Phase 0 - orientation

### 2026-09-26 · db:load failed on Windows

Expected `npm run db:load` to work out of the box.
Got: `ENOENT: no such file or directory, open 'F:\F:\interview\rhino\remoteops\db\schema.sql'`.
Cause: `new URL(...).pathname` gives `/F:/interview/...` on Windows. Node treats it as a path on
the current drive, so the drive letter appears twice.
Fix: `fileURLToPath(new URL(...))` in `scripts/load-db.js`. The DB loads now.
Made the same change to `DIST` in `server/index.js`.

### 2026-09-27 · my own fix broke the server

I changed `server/index.js` without adding the import and did not run the server after.
Got: `ReferenceError: fileURLToPath is not defined` at `server/index.js:22`. The server did not
start at all.
Fix: `import { fileURLToPath } from 'node:url';`. The server starts on :8080. Commit `623de88`.
Lesson: run it after every change, even a one-line change.

### 2026-09-27 · the starting line

- `check-jwt.js`: 0 passed, 43 failed. All hit the `verifyAccessToken` TODO.
- `check-permissions.js`: crashes on the first case. `resolve()` is a stub.
- `check-personalisation.js`: fails on the same stub.
- `check-api.js`: `dana logs in` got 404, want 200. Then it aborts.

Surprise: login is 404, not 401. I thought login came with the token signing. It does not.
`server/routes/index.js` registers nothing, so every `/v1/*` route is mine, login included.

### 2026-09-27 · my personalised fixture

`npm run fingerprint` gives: role `reviewer` (rank 35), permission `device:reboot`,
org Ironside Labs. `device:reboot` is allowed on `dev_p_bb3398_a` and denied on `dev_p_bb3398_b`.
Reviewer baseline: `device:list`, `device:view`, `user:invite`, `user:remove`.

Two things I noticed:
- Rank 35 is between operator (30) and admin (40), but reviewer has `user:invite` and
  `user:remove`, which operator lacks, and lacks `device:control`, which operator has.
  So rank says nothing about permissions. The engine must read `role_permissions`.
- Reviewer can remove users but has no `user:read`. Open question: can reviewer list the
  members it is allowed to remove? No document covers this.

## Phase 1 - token verification

<!-- What did you expect each failure mode to look like before you ran it? Which one behaved
differently, and what did that tell you? -->

### 2026-09-27 · predictions, before writing any code

1. `timingSafeEqual` throws `RangeError` when the buffers differ in length. A truncated
   signature would then be a 500, not a 401. I need a length check first.
2. `Buffer.from('!!!', 'base64url')` does not throw. It skips bad characters. So a garbage
   signature is caught by the length or compare check, not by decoding.
3. A header of `null` parses fine as JSON. `header.alg` would then throw `TypeError` (500).
   I need an "is it an object" check.
4. Order: check the signature before parsing the payload. Then nothing unsigned gets parsed.

### 2026-09-27 · checked the predictions in node, then built it

- 1 held: `RangeError ERR_CRYPTO_TIMING_SAFE_EQUAL_LENGTH`.
- 2 held, with a detail I missed: `'!!!not-base64!!!'` does not decode to empty. The valid
  characters still decode, giving 7 bytes of junk. So only the length and compare checks
  stop it.
- 3 held: `TypeError`. Added `decodeObject`, which returns null for null, strings and arrays.

`check-jwt.js`: 43 passed, 0 failed, first run. Extra probes (`null` header, array header)
also give 401, not 500.
`check-api.js` still fails: `dana logs in` 404. Next up is the login route.

## Phase 2 - caller context and the resolution engine

<!-- The model you started with, the observation that broke it, the model you moved to. -->

### 2026-09-27 · engine passes the suites, probes find 3 bugs

Engine done (`server/permissions.js`, commit `57b3cb9`).
`check-permissions.js` 35/35, `check-personalisation.js` 18/18, on the first draft already.

The suites passed, but `scripts/probe-engine.js` found 3 bugs they do not cover:

1. The draft read "hold it at that scope" as "on any device", and I accepted that. Wrong:
   a viewer with `grant:create` and `device:control` on one device could grant
   `device:control` org-wide. Now an org-wide grant needs the permission on every device
   (`orgMode 'every'`). Nav still uses `'any'`.
2. A device moved to another org kept its old grants. Its allow still showed in the old
   org's nav. Added `d.org_id = g.org_id` in `loadGrants`.
3. I compared ISO times as text. `'09:00:00Z'` vs `'09:00:00.000Z'`: `.` sorts before `Z`,
   so a grant stayed alive at its expiry. `windowState` now compares `Date.parse` numbers.

Checked the probe catches them: with bugs 1 and 2 put back, it reports 3 FAILs.

### 2026-09-27 · the union is not tested by the suites

Org-level: device-scoped allows count, device-scoped denies do not.
Robin (reviewer, Ironside) gets `device:reboot` at org level: `allow` from
`grt_p_bb3398_allow`. On `dev_p_bb3398_b` it is `explicit_deny`.
I made no prediction about this earlier; Phase 0 only noted the two grants.

Flipped nav to `'every'` to see what breaks. Both suites still passed, 35/35 and 18/18.
So nothing shipped tests the union. The probe does: with `'every'`, 4 nav checks fail,
including Robin's `device:reboot`.

### 2026-09-27 · context.js

Docs clash: §1 says suspension bumps `pv`, §10 says a suspended token gets 403. Checked
freshness first, a suspended member would always get 401 TOKEN_STALE. So suspended skips it.
Wrong prediction: my probe assumed owner has every permission. Failed: owner is `implicit`
deny on `device:reboot`, which is in no role's baseline. The engine was right; fixed the probe.
`probe-context.js` 23/23, commit `81d5c13`.

### 2026-09-27 · login, switch org, me

No document says which org a login lands in. Picked earliest `joined_at` active membership.
Dana and Sam both joined Acme first, and the tests expect Acme. Alphabetical would pass too,
so the tests do not settle it.
Measured: without a dummy scrypt, unknown email took 1.9 ms, wrong password 49.0 ms (median
of 5). That is an account oracle. With it: 56.4 vs 56.8 ms. `probe-auth.js` 21/21.
`check-api.js`: `Acme token against Globex -> 404` passes, but only because the devices
route does not exist yet. Not a real pass until that route is built. `no token -> 401`
gets 404 for the same reason: the router matches the path before auth runs.

### 2026-09-27 · predictions before devices, grants, refresh

1. `GET /devices` runs the same number of queries for 5 devices or 100. Guess: about 10.
2. With the devices route in place, Acme-on-Globex 404s in `context.js`. Remove the org check
   there and it becomes 200 with Acme's devices, not a 404.
3. An unknown permission fails the insert with `SQLITE_CONSTRAINT_FOREIGNKEY`.

### 2026-09-27 · results: all three held

1. `GET /devices`: 10 queries with 4 rows, 10 with 104. To check the counter works, I
   resolved per row on purpose: 26 and 426. So it would catch an N+1.
2. Org check removed from `context.js`: Acme token on the Globex path got **200**. Put back:
   404. So the check-api test now passes for the right reason (it was a false pass before).
3. `device:teleport` gets 400 `unknown_permission`, which only comes from the FK catch. The
   transaction rolled back: no grant row without permissions.

### 2026-09-27 · devices, grants, refresh: things no document settles

- `GET /devices/:id` without `device:view`: 404, not 403. The list hides the row, so a 403
  here would confirm the id exists. Still audited, as `not_visible`.
- Revoking a grant on yourself: 403. Revoking your own deny is a self-grant by another route.
- Transfer revokes the device's grants. My engine fix only hides them while the device is
  away. Moved back, they would work again.
- Decommission ends sessions with `device_transferred`. The schema has no other fit.
- Refresh: check, then rotate. Safe only because handlers are synchronous in one process.
- `probe-routes.js` 48/48. `check-api.js`: 16 ok, stops at audit and sessions (not built).

### 2026-09-27 · sessions and the audit list

Race test: two server processes, one DB, 10 rounds of two parallel control starts.
Every round: one 201, one 409. Dropped the unique index to check the probe: every round
became 201 + 201, two active control sessions on one device. The index is the only lock.
Wrong prediction in my probe: Sam asked for `terminal` and got 403, not 409. The seed has
an org-wide deny on his `device:terminal`. The engine was right; changed the probe to control.
Bug in my code: TTL came out as 60.0000167 min. `started_at` came from SQLite's clock,
`expires_at` from JS. Now both come from one `startedAt`.
Expired sessions stay `active` in the table until read. `expireSessions` marks them ended
before reads and before inserts. Otherwise an expired control would still hold the index.
`GET /sessions/:id` you may not read: 404, like a device you cannot view.
`check-api.js`: 29 ok. Stops at `owner demotes Sam` (members routes not built).
`the live session SURVIVES` passes, but falsely: the demotion never happened.

## Phase 3 - orgs, members, invites

<!-- Anything no document states. Invite lifecycle states. -->

## Phase 4 - devices and grants

<!-- Two grants disagree, or grant scope and question scope differ. Predicted vs got. -->

## Phase 5 - sessions

<!-- Two permissions, one device. What order keeps the two failure reasons distinct? -->

## Phase 6 - audit

<!-- What counts as an auditable event, and why. -->

## Phase 7 - the console

<!-- Where the server's answer and your instinct disagreed about what should be on screen. -->

## Phase 8 - hardening

<!-- What you measured, what you fixed, what you left alone and why. -->

## Open threads

- Reviewer has `user:remove` without `user:read`. Not settled yet.
- Refresh from two tabs at once: the second looks like a replay and logs the user out.
- A transfer writes one audit row, in the old org. The new org's log does not show it.
- `GET /grants` lists grants on devices the reader may not be able to view (leaks the id).
- `POST /devices` checks `device:provision` at org level ('any'): one device's grant is enough.
