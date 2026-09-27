// Admin: rename (org:update) and delete (org:delete). An admin sees the card for
// rename alone; delete is absent unless org:delete is held.

import React from 'react';
import { api, applySession, refresh } from '../api.js';
import { Action, useRun } from '../ui.jsx';

export function Admin({ session }) {
  const org = session.orgs.find((o) => o.id === session.orgId);
  const run = useRun();

  async function rename() {
    const name = window.prompt('New name for this organization', org.name);
    if (!name?.trim() || name.trim() === org.name) return;
    await run(async () => {
      await api('PATCH', `/orgs/${session.orgId}`, { name: name.trim() });
      applySession({ ...session, ...(await api('GET', '/auth/me')) }); // keeps the token
    });
  }

  async function remove() {
    if (window.prompt(`Type the name to delete it for everyone: ${org.name}`) !== org.name) return;
    await run(async () => {
      await api('DELETE', `/orgs/${session.orgId}`);
      // This org's token is dead now. Land in the next org, or on the login form if none.
      await refresh().catch(() => {});
    });
  }

  return (
    <section>
      <h2>Admin</h2>
      <p>{org.name} · theme {org.theme}</p>
      <div className="toolbar">
        <Action set={session.permissions} perm="org:update" testid="rename-org" onClick={rename}>Rename organization</Action>
        <Action set={session.permissions} perm="org:delete" testid="delete-org" className="danger" onClick={remove}>
          Delete organization
        </Action>
      </div>
    </section>
  );
}
