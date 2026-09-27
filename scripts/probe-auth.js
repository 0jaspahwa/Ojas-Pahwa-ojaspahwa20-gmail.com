// Probes for the auth routes: login, switch org, me.
// Spawns the server on a throwaway database, like check-api.js.
//
//   node scripts/probe-auth.js

import { spawn, execFileSync } from 'node:child_process';
import { rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { openDatabase } from '../server/db.js';

const PORT = 8124;
const BASE = `http://localhost:${PORT}/v1`;
const DB = join(tmpdir(), `probe-auth-${process.pid}.db`);

execFileSync(process.execPath, ['scripts/load-db.js'], { env: { ...process.env, DATABASE_FILE: DB }, stdio: 'ignore' });
const server = spawn(process.execPath, ['server/index.js'], {
  env: { ...process.env, DATABASE_FILE: DB, PORT: String(PORT), NODE_ENV: 'production', JWT_SECRET: 'probe-secret' },
  stdio: ['ignore', 'ignore', 'inherit'],
});
await new Promise((r) => setTimeout(r, 1200));

let pass = 0, fail = 0;
const check = (label, got, want) => {
  const ok = JSON.stringify(got) === JSON.stringify(want);
  ok ? pass++ : fail++;
  console.log(`${ok ? ' ok  ' : ' FAIL'}  ${label.padEnd(54)} ${ok ? '' : `got ${JSON.stringify(got)} want ${JSON.stringify(want)}`}`);
};

async function call(method, path, { token, body } = {}) {
  const headers = {};
  if (token) headers.authorization = `Bearer ${token}`;
  if (body) headers['content-type'] = 'application/json';
  const t0 = performance.now();
  const res = await fetch(BASE + path, { method, headers, body: body ? JSON.stringify(body) : undefined });
  const ms = performance.now() - t0;
  const text = await res.text();
  return { status: res.status, body: text ? JSON.parse(text) : null, cookie: res.headers.get('set-cookie'), ms };
}
const login = (email, password = 'demo1234', orgId) =>
  call('POST', '/auth/login', { body: { email, password, ...(orgId ? { orgId } : {}) } });
const shape = (r) => ({ status: r.status, code: r.body?.error?.code, message: r.body?.error?.message });

try {
  console.log('\n== login: no enumeration oracle ==');
  const wrongPw = await login('dana@example.test', 'nope');
  const noUser = await login('nobody@example.test', 'nope');
  check('wrong password and unknown email read the same', shape(wrongPw), shape(noUser));
  check('  ...both 401 UNAUTHENTICATED', [wrongPw.status, wrongPw.body.error.code], [401, 'UNAUTHENTICATED']);
  // Median of 5 each: an unknown email still pays for scrypt.
  const median = async (email) => {
    const t = [];
    for (let i = 0; i < 5; i++) t.push((await login(email, 'nope')).ms);
    return t.sort((a, b) => a - b)[2];
  };
  const [mWrong, mNone] = [await median('dana@example.test'), await median('nobody@example.test')];
  console.log(`        median ms: wrong password ${mWrong.toFixed(1)}, unknown email ${mNone.toFixed(1)}`);
  check('  ...unknown email not much faster (ratio > 0.5)', mNone / mWrong > 0.5, true);

  console.log('\n== login: input ==');
  check('missing password -> 400', (await call('POST', '/auth/login', { body: { email: 'dana@example.test' } })).status, 400);
  check('email as a number -> 400', (await call('POST', '/auth/login', { body: { email: 5, password: 'x' } })).status, 400);
  check('upper-case email still logs in', (await login('DANA@Example.TEST')).status, 200);

  console.log('\n== login: which org ==');
  const dana = await login('dana@example.test');
  check('no orgId: earliest joined (Acme, owner)', [dana.body.orgId, dana.body.role], ['org_acme', 'owner']);
  const danaG = await login('dana@example.test', 'demo1234', 'org_globex');
  check('orgId given: Globex, viewer', [danaG.body.orgId, danaG.body.role], ['org_globex', 'viewer']);
  check('orgId she is not in -> 401', (await login('owner@acme.test', 'demo1234', 'org_globex')).status, 401);
  check('permissions come back, with provenance', dana.body.permissions['org:delete'], { effect: 'allow', source: 'role:owner', reason: null });

  console.log('\n== login: refresh cookie ==');
  check('cookie is HttpOnly, Secure, SameSite=Strict',
    ['HttpOnly', 'Secure', 'SameSite=Strict'].every((f) => dana.cookie?.includes(f)), true);
  check('no refresh token in the JSON body', JSON.stringify(dana.body).includes(dana.cookie.split(/[=;]/)[1]), false);
  const raw = dana.cookie.split(/[=;]/)[1];
  const db = openDatabase(DB);
  check('refresh token stored hashed, not raw', db.prepare('SELECT count(*) n FROM refresh_tokens WHERE token_hash = ?').get(raw).n, 0);
  db.close();

  console.log('\n== switch org ==');
  const sw = await call('POST', '/auth/token', { token: dana.body.token, body: { orgId: 'org_globex' } });
  check('Acme token -> Globex token', [sw.status, sw.body.orgId, sw.body.role], [200, 'org_globex', 'viewer']);
  check('switch to an org you are not in -> 404', (await call('POST', '/auth/token', { token: (await login('owner@acme.test')).body.token, body: { orgId: 'org_globex' } })).status, 404);
  check('switch to a made-up org -> 404', (await call('POST', '/auth/token', { token: dana.body.token, body: { orgId: 'org_nope' } })).status, 404);
  check('no orgId -> 400', (await call('POST', '/auth/token', { token: dana.body.token, body: {} })).status, 400);
  check('no bearer -> 401', (await call('POST', '/auth/token', { body: { orgId: 'org_globex' } })).status, 401);

  console.log('\n== me ==');
  const me = await call('GET', '/auth/me', { token: sw.body.token });
  check('me follows the token, not a server-side "current org"', [me.body.orgId, me.body.role], ['org_globex', 'viewer']);
  check('me returns no token', 'token' in me.body, false);
  const meA = await call('GET', '/auth/me', { token: dana.body.token });
  check('old Acme token still says Acme', meA.body.orgId, 'org_acme');
} finally {
  server.kill();
  await new Promise((r) => setTimeout(r, 300));
  for (const s of ['', '-wal', '-shm']) rmSync(DB + s, { force: true });
}

console.log(`\n${fail === 0 ? 'ALL PASS' : 'FAILURES'} — ${pass} passed, ${fail} failed\n`);
process.exit(fail === 0 ? 0 : 1);
