# BUILD-LOG

Entries are in the order the work happened. I built out of the phase order (devices, grants
and sessions before members), so Phases 3-6 point to where their entries are.

**Where to find each kind of entry**

| Kind | Entry |
|---|---|
| A wrong prediction | Phase 2 · context.js ("my probe assumed owner has every permission"); Phase 2 · sessions ("Sam asked for terminal and got 403, not 409"); Phase 3 · "what IMMEDIATE actually buys (I had it wrong)" |
| A reversed decision | Phase 2 · engine ("hold it at that scope" = any device, then any + every); Phase 8 · invite accept (password required, then attach without one) |
| A doc gap I settled | Phase 2 · login ("no document says which org a login lands in"); Phase 2 · "devices, grants, refresh: things no document settles" |
| A DB guarantee I leaned on | Phase 2 · sessions (unique index dropped: 201 + 201 every round); Phase 2 · results (`device:teleport` rejected by the FK, transaction rolled back) |
| A bug in my own code | Phase 0 · "my own fix broke the server"; Phase 2 · sessions (TTL 60.0000167 min, two clocks); Phase 3 · members (a refusal audited twice) |
| Something measured | Phase 2 · login (1.9 ms vs 49.0 ms without dummy scrypt); Phase 2 · results (10 queries at 4 and 104 rows, 26/426 with N+1); Phase 7 · inspector (900/900, 35/900 broken) |

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

## Phase 3 - orgs, members, invites (built after sessions)

### 2026-09-27 · members, orgs, invites: check-api green

`check-api.js` 66/66. `the live session SURVIVES` is now a real pass.
Bug in my own code, found by reading it: a refused role change was audited twice (a helper
wrapped in `auditDenials`, called inside another). Probe now checks one refusal = one row.
"Owner" in the rank rules is the top-ranked role from `roles`, not the string `'owner'`.
Expired invites still count as live for `one_live_invite_per_email` (it only checks
`accepted_at` and `revoked_at`). Without retiring them, that email could never be invited again.
Accepting an invite for an existing account needs that account's password. Otherwise the
invite token alone would sign someone in to an account.
Removing a member revokes their grants, same reason as transfer: a re-invite would revive them.

### 2026-09-27 · what IMMEDIATE actually buys (I had it wrong)

I thought IMMEDIATE stopped a double win in the races. Removed it and re-ran the probe:
data stayed right (one user, one owner every round), but one accept round in five gave
`500 SQLITE_BUSY_SNAPSHOT`. WAL already refuses the loser. IMMEDIATE makes the loser wait
and get a clean 409. Fixed my code comments, which claimed the wrong thing.

## Phase 4 - devices and grants

Built before members. Entries are under Phase 2: "predictions before devices, grants,
refresh", "results: all three held", and "devices, grants, refresh: things no document settles".

## Phase 5 - sessions

Built before members. Entry under Phase 2: "sessions and the audit list". The two failure
reasons stay apart because `assertCanStartSession` checks `session:start` first, then the mode
permission, on one resolved set.

## Phase 6 - audit

### 2026-09-27 · what counts as an auditable event (written up at the end)

Decided when I wrote `audit.js` (`d513042`); written here at the end, so it is a summary.
- Every write that succeeds: one row, inside the same transaction as the change.
- Every 403: one deny row with the reason, via `auditDenials`. Probe: "one refusal writes
  one deny row" (it was two, see Phase 3).
- A `GET` on a device you cannot view: 404 to you, but a deny row (`not_visible`), because
  that is someone probing ids.
- Not audited: successful reads, logins, other 404s. Reads would drown the denials, and a
  404 on an unknown id says nothing about who tried what.

## Phase 7 - the console

<!-- Where the server's answer and your instinct disagreed about what should be on screen. -->

### 2026-09-27 · console built in 4 steps, Playwright 25/25

Failed first: every test, at browser launch. Playwright 1.63 wanted Chromium headless
shell 1243; only 1223 was installed. `npx playwright install chromium` fixed it.
After that, each step passed its tests on the first run: shell 9/9, devices 9/9, cards 7/7,
then the full suite 25/25.
Thought ahead, before a test caught it: React StrictMode runs effects twice in dev. Two
`POST /auth/refresh` with one cookie look like a replay, and my own server would revoke the
family and sign the user out. So `refresh()` in `web/api.js` keeps one call in flight.
Sign-out had nowhere to go: the cookie has `Path=/v1/auth/refresh`, so it is only sent there.
Added `DELETE /auth/refresh`. Without it, a reload after sign-out logs you straight back in.
The role picker needed the role list without a list in `web/`: added `GET /orgs/:org/roles`.
The grant checkboxes are the keys of the resolved set, so `device:reboot` shows up too.

### 2026-09-27 · manual check, and a dev-server loop

`npm run dev` restarted 8 times in 6 seconds, so the browser got `ERR_CONNECTION_RESET`.
Split it: loops only with `--watch` plus Vite; not with `--watch-path` alone, not in
production. This machine has Node 20; `.nvmrc` says 22. On Node 20, `--watch` still watches
imported modules even with `--watch-path`. Dropped `--watch`: 0 restarts, and touching a
server file still restarts once. Commit `755bba9`.
Then signed in as Sam. Acme (operator): Devices + Sessions, Control on all 5 rows, no
Terminal, no Audit. Globex (auditor): Audit card present, 0 Control buttons, theme amber.
Web storage empty in both.

### 2026-09-27 · the "why?" inspector (my extra)

`GET /users/:id/explain`: same gate as `/effective`, so I moved that gate into one helper
(`askAbout` in `orgs.js`) instead of copying it.
Probe: `explain()` vs `resolve()` for every membership x permission x device: 900/900.
First run never hit "not a member": the fixture has no removed member. Added one, still
900/900, now every trace branch is reached.
Broke it on purpose (explain skipped deny grants): 35 of 900 disagreed. Restored: 900/900.
The baseline step used to be an English sentence from the server. Changed it to data
(`role`, `contains`), so the console writes the words and the server stays wordless.
UI: "Why?" in People (anyone), and "My access" for everyone (yourself only). The permission
list is the keys of the server's set, so `device:reboot` shows up. 4 new Playwright tests;
suite 29/29.
Manual check hit my own refresh cookie: the preview browser still held Sam's session from
earlier, so the page opened as Sam, not the login form. Working as designed.
`db:reset` was `rm -f ... && npm run db:load`: `rm` fails on Windows. `load-db.js` already
deletes the files, so the script is now just `node scripts/load-db.js`.

## Phase 8 - hardening

<!-- What you measured, what you fixed, what you left alone and why. -->

### 2026-09-27 · invite accept for an existing account: reversed

Had: an existing account must give its password, else 401 (`409b2f4`). Too strict: the
person owns the email and may only want the membership. Now: no password attaches the
membership, 200, no token, no cookie. Right password also signs in. Wrong password: 401,
nothing attached. The token alone still never signs anyone in. 3 new probe lines, 39/39.
Also renamed the My access test id to `my-access`: it was `nav-me`, which made a seventh
`nav-*` card for an owner. New test: an owner has exactly six.

### 2026-09-27 · what I measured, fixed, and left alone

Probes, beyond the shipped suites (all green at the end):
- `probe-engine` 15, `probe-context` 23, `probe-auth` 21, `probe-routes` 48,
  `probe-sessions` 31, `probe-members` 39, `probe-explain` 900.
- Six were checked by breaking the code on purpose: engine bugs put back (`probe-engine`,
  3 FAILs), dummy scrypt removed (`probe-auth`, ratio FAIL), N+1 (`probe-routes`, 26/426
  queries), unique index dropped (`probe-sessions`, 201 + 201 every round), IMMEDIATE removed
  (`probe-members`, a 500 in 1 of 5 rounds), explain skipping denies (`probe-explain`, 35 of
  900 wrong). `probe-context` was not broken on purpose.

Races, with two server processes on one database file:
- parallel control starts: one 201, one 409, 10 of 10 rounds. The index is the only lock.
- parallel invite accepts: one 200, one 409, 5 of 5.
- two owners demoting each other: one wins, one owner left, 5 of 5.
- IMMEDIATE does not protect the data (WAL already does); it gives the loser a 409, not a 500.

Measured: login 1.9 ms vs 49.0 ms without the dummy scrypt, 56.4 vs 56.8 ms with it.
`GET /devices` 10 queries at 4 rows and at 104. Dev server: 8 restarts in 6 s on Node 20
with `--watch`, 0 without.

Left alone, on purpose: see "Deliberately not built" in DECISIONS.md and the open threads
below. The biggest is the two-tab refresh race.

### 2026-09-27 · clean checkout: Playwright had nothing to serve

Filling the form ("we run it exactly as written"), I ran `npx playwright test` on a fresh clone
that was never built. Every test timed out after 30 s on an empty page. `dist/` is git-ignored,
and the test server serves `dist/`. My 30/30 only passed because my folder had an old build.
Fix: the Playwright web server runs `npm run build` first. Clean clone, no build: 30/30.
Lesson: "works on my machine" included a build artifact I had forgotten was there.

## Open threads

- Reviewer has `user:remove` without `user:read`. Not settled yet.
- Refresh from two tabs at once: the second looks like a replay and logs the user out.
- A transfer writes one audit row, in the old org. The new org's log does not show it.
- `GET /grants` lists grants on devices the reader may not be able to view (leaks the id).
- `POST /devices` checks `device:provision` at org level ('any'): one device's grant is enough.
