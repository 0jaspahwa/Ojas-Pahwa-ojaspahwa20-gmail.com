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

## Where this repo argues with itself

<!-- For each contradiction: quote both statements, say which one you built against, and why. -->

## Deliberately not built

<!-- What you chose not to build, and why. -->
