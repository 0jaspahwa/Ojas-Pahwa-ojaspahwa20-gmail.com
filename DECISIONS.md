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

## Where this repo argues with itself

<!-- For each contradiction: quote both statements, say which one you built against, and why. -->

## Deliberately not built

<!-- What you chose not to build, and why. -->
