// Sign in. The error shows the server's words as-is: a wrong password and an unknown
// account read the same, because the server answers them the same.

import React, { useState } from 'react';
import { call, applySession } from './api.js';

export function Login({ notice }) {
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState(null);
  const [busy, setBusy] = useState(false);

  async function submit(e) {
    e.preventDefault();
    setError(null);
    if (!email.trim() || !password) {
      setError({ code: 'VALIDATION', message: `Enter your ${!email.trim() ? 'email' : 'password'} to sign in.` });
      return;
    }
    setBusy(true);
    try {
      applySession(await call('POST', '/auth/login', { email, password }));
    } catch (err) {
      setError(err);
      setBusy(false);
    }
  }

  return (
    <main className="login">
      <form data-testid="login-form" onSubmit={submit} noValidate>
        <h1>RemoteOps</h1>
        {notice && <p className="notice" role="status">{notice}</p>}
        <label>Email
          <input data-testid="login-email" type="email" autoComplete="username"
                 value={email} onChange={(e) => setEmail(e.target.value)} />
        </label>
        <label>Password
          <input data-testid="login-password" type="password" autoComplete="current-password"
                 value={password} onChange={(e) => setPassword(e.target.value)} />
        </label>
        {error && (
          <p className="message error" data-testid="login-error" data-error-code={error.code} role="alert">
            {error.message}
          </p>
        )}
        <button data-testid="login-submit" type="submit" disabled={busy}>
          {busy ? 'Signing in…' : 'Sign in'}
        </button>
      </form>
    </main>
  );
}
