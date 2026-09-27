// /invite/:token. Shows only what the public endpoint returns (org name, role, email),
// so a bad link reveals nothing about any org.

import React, { useEffect, useState } from 'react';
import { call } from './api.js';

const WHY = {
  404: 'This invite link is not valid.',
  409: 'This invite has already been used.',
  410: 'This invite has expired or was cancelled.',
};

export function Invite({ token, onAccepted }) {
  const [invite, setInvite] = useState(null);
  const [error, setError] = useState(null);
  const [name, setName] = useState('');
  const [password, setPassword] = useState('');
  const path = `/invites/${encodeURIComponent(token)}`;

  useEffect(() => { call('GET', path).then(setInvite).catch(setError); }, [path]);

  async function submit(e) {
    e.preventDefault();
    setError(null);
    try {
      await call('POST', `${path}/accept`, { name, password });
      // Accepting also set a refresh cookie. Drop it: the person signs in on purpose.
      await call('DELETE', '/auth/refresh').catch(() => {});
      onAccepted();
    } catch (err) {
      setError(err);
    }
  }

  const errorBox = error && (
    <p className="message error" data-testid="invite-error" data-error-code={error.code} role="alert">
      {WHY[error.status] && !invite ? WHY[error.status] : error.message}
    </p>
  );

  return (
    <main className="login">
      {!invite ? (
        <div className="panel-box">{errorBox ?? <p>Checking your invite…</p>}</div>
      ) : (
        <form onSubmit={submit}>
          <h1>Join {invite.orgName}</h1>
          <p>You have been invited as <strong data-testid="invite-role">{invite.role}</strong>.</p>
          <label>Email <input data-testid="invite-email" value={invite.email} readOnly /></label>
          <label>Your name <input data-testid="invite-name" value={name} onChange={(e) => setName(e.target.value)} /></label>
          <label>Password (8 or more characters; your current one if you already have an account)
            <input data-testid="invite-password" type="password" value={password} onChange={(e) => setPassword(e.target.value)} />
          </label>
          {errorBox}
          <button data-testid="invite-submit" type="submit">Accept invite</button>
        </form>
      )}
    </main>
  );
}
