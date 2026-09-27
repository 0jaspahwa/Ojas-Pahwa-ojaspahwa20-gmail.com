// People: members, roles, suspend/remove, invite.
// Your own row has no controls: the server refuses self-changes, so offering them
// would only produce an error.

import React, { useState } from 'react';
import { api } from '../api.js';
import { Action, allowed, useLoad, useRun } from '../ui.jsx';
import { Why } from './Why.jsx';

export function People({ session }) {
  const base = `/orgs/${session.orgId}`;
  const perms = session.permissions;
  const [data, reload] = useLoad(() =>
    Promise.all([api('GET', `${base}/members`), api('GET', `${base}/roles`)])
      .then(([m, r]) => ({ members: m.members, roles: r.roles })));
  const [inviting, setInviting] = useState(false);
  const run = useRun();

  async function act(fn, done) {
    await run(fn, done);
    reload();
  }

  if (!data) return <p className="empty">Loading people…</p>;

  return (
    <section>
      <div className="toolbar">
        <h2>People</h2>
        <Action set={perms} perm="user:invite" testid="invite-user" onClick={() => setInviting(!inviting)}>+ Invite</Action>
      </div>

      {inviting && <InviteForm base={base} roles={data.roles} />}

      <table>
        <thead><tr><th>Name</th><th>Email</th><th>Role</th><th>Status</th><th>Actions</th></tr></thead>
        <tbody>
          {data.members.map((m) => {
            const me = m.userId === session.user.id;
            return (
              <tr key={m.userId} data-testid="user-row" data-user-id={m.userId}>
                <td>{m.name}{me && ' (you)'}</td>
                <td>{m.email}</td>
                <td>
                  {!me && allowed(perms, 'user:role:update') ? (
                    <select data-testid="role-select" data-permission="user:role:update" data-state="unlocked"
                            value={m.role} aria-label={`Role of ${m.name}`}
                            onChange={(e) => act(() => api('PATCH', `${base}/members/${m.userId}`, { role: e.target.value }),
                                                 `${m.name} is now ${e.target.value}.`)}>
                      {data.roles.map((r) => <option key={r.key} value={r.key}>{r.key}</option>)}
                    </select>
                  ) : m.role}
                </td>
                <td>{m.status}</td>
                <td className="actions">
                  {!me && (
                    <>
                      <Action set={perms} perm="user:remove" testid="suspend-user"
                              onClick={() => act(() => api(m.status === 'suspended' ? 'DELETE' : 'POST', `${base}/members/${m.userId}/suspend`),
                                                 `${m.name} was ${m.status === 'suspended' ? 'reinstated' : 'suspended'}.`)}>
                        {m.status === 'suspended' ? 'Reinstate' : 'Suspend'}
                      </Action>
                      <Action set={perms} perm="user:remove" testid="remove-user" className="danger"
                              onClick={() => window.confirm(`Remove ${m.name} from this organization?`) &&
                                act(() => api('DELETE', `${base}/members/${m.userId}`), `${m.name} was removed.`)}>
                        Remove
                      </Action>
                    </>
                  )}
                </td>
              </tr>
            );
          })}
        </tbody>
      </table>

      <Why session={session} members={data.members} />
    </section>
  );
}

// No email is sent (BRIEF: out of scope), so the link is shown once to copy.
function InviteForm({ base, roles }) {
  const [email, setEmail] = useState('');
  const [role, setRole] = useState(roles[roles.length - 1]?.key);
  const [link, setLink] = useState(null);
  const run = useRun();

  async function submit(e) {
    e.preventDefault();
    const made = await run(() => api('POST', `${base}/invites`, { email, role }));
    if (made) setLink(`${location.origin}/invite/${made.inviteToken}`);
  }

  return (
    <form className="panel" onSubmit={submit}>
      <label>Email <input type="email" value={email} onChange={(e) => setEmail(e.target.value)} required /></label>
      <label>Role
        <select value={role} onChange={(e) => setRole(e.target.value)}>
          {roles.map((r) => <option key={r.key} value={r.key}>{r.key}</option>)}
        </select>
      </label>
      <div><button type="submit">Create invite</button></div>
      {link && <p>Send this link. It is shown once and works once: <code>{link}</code></p>}
    </form>
  );
}
