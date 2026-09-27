// The signed-in console: org switcher, nav, and the active card.
//
// Nav comes from the org-level permission set the server sent with the session.
// Each card fetches its own data when it mounts, so opening it again refetches.

import React, { useState } from 'react';
import { api, applySession, signOut } from './api.js';
import { Action, Messages, allowed, useRun } from './ui.jsx';
import { Devices } from './views/Devices.jsx';

// Filled in card by card.
const Soon = () => <p>Coming next.</p>;
const [People, Grants, Sessions, Audit, Admin] = [Soon, Soon, Soon, Soon, Soon];

// [key, label, the permission(s) that show it, component]
const CARDS = [
  ['devices', 'Devices', ['device:list'], Devices],
  ['people', 'People', ['user:read'], People],
  ['grants', 'Grants', ['user:read'], Grants],
  ['sessions', 'Sessions', ['session:view'], Sessions],
  ['audit', 'Audit', ['audit:read'], Audit],
  ['admin', 'Admin', ['org:update', 'org:delete'], Admin],
];

export function Shell({ session }) {
  return (
    <Messages>
      <ShellBody session={session} />
    </Messages>
  );
}

function ShellBody({ session }) {
  const perms = session.permissions;
  const org = session.orgs.find((o) => o.id === session.orgId);
  const cards = CARDS
    .map(([key, label, gates, View]) => ({ key, label, View, perm: gates.find((p) => allowed(perms, p)) }))
    .filter((c) => c.perm);
  const [view, setView] = useState(cards[0]?.key);
  const run = useRun();
  const Active = cards.find((c) => c.key === view)?.View;

  const switchTo = (id) => run(async () => applySession(await api('POST', '/auth/token', { orgId: id })));

  async function createOrg() {
    const name = window.prompt('Name of the new organization');
    if (!name?.trim()) return;
    await run(async () => {
      const made = await api('POST', '/orgs', { name: name.trim() });
      applySession(await api('POST', '/auth/token', { orgId: made.id }));
    });
  }

  return (
    <div className="shell" data-testid="app-shell" data-org-id={session.orgId} data-org-theme={org?.theme}>
      <header>
        <div className="brand">
          <strong>{org?.name}</strong>
          <span className="role">signed in as {session.user.name} · <span data-testid="active-role">{session.role}</span></span>
        </div>
        <nav className="orgs" aria-label="Organizations">
          {session.orgs.map((o) => (
            <button key={o.id} type="button" data-testid="org-option" data-org-id={o.id} data-org-theme={o.theme}
                    aria-current={o.id === session.orgId} onClick={() => o.id !== session.orgId && switchTo(o.id)}>
              {o.name}
            </button>
          ))}
          <button type="button" data-testid="create-org" onClick={createOrg}>+ New org</button>
          <button type="button" className="link" data-testid="sign-out" onClick={() => signOut()}>Sign out</button>
        </nav>
      </header>

      <nav className="cards" aria-label="Sections">
        {cards.map((c) => (
          <Action key={c.key} set={perms} perm={c.perm} testid={`nav-${c.key}`}
                  aria-current={c.key === view} onClick={() => setView(c.key)}>
            {c.label}
          </Action>
        ))}
      </nav>

      <main>
        {Active ? <Active key={view} session={session} /> : <p>You have no access to anything in this organization.</p>}
      </main>
    </div>
  );
}
