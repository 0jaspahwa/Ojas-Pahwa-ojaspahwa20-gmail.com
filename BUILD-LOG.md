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

## Phase 2 - caller context and the resolution engine

<!-- The model you started with, the observation that broke it, the model you moved to. -->

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
