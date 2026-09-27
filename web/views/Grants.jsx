// Grants: list, create, revoke.
// The permission checkboxes are the catalogue the server sent with the session (every
// key of the resolved set), so a permission added to the database appears here too.

import React, { useState } from 'react';
import { api } from '../api.js';
import { Action, allowed, useLoad, useRun } from '../ui.jsx';

export function Grants({ session }) {
  const base = `/orgs/${session.orgId}`;
  const perms = session.permissions;
  const [data, reload] = useLoad(() =>
    Promise.all([
      api('GET', `${base}/grants`),
      api('GET', `${base}/members`),
      allowed(perms, 'device:list') ? api('GET', `${base}/devices`) : { devices: [] },
    ]).then(([g, m, d]) => ({ grants: g.grants, members: m.members, devices: d.devices })));
  const [creating, setCreating] = useState(false);
  const run = useRun();

  if (!data) return <p className="empty">Loading grants…</p>;
  const person = (id) => data.members.find((m) => m.userId === id)?.name ?? id;
  // A device the caller cannot view is not named, not even by id.
  const device = (id) => (id === null ? 'whole org' : data.devices.find((d) => d.id === id)?.name ?? 'a device you cannot see');

  async function revoke(g) {
    await run(() => api('DELETE', `${base}/grants/${g.id}`), 'Grant revoked.');
    reload();
  }

  return (
    <section>
      <div className="toolbar">
        <h2>Grants</h2>
        <Action set={perms} perm="grant:create" testid="new-grant" onClick={() => setCreating(!creating)}>+ New grant</Action>
      </div>

      {creating && (
        <NewGrant base={base} data={data} session={session} onDone={() => { setCreating(false); reload(); }} />
      )}

      {data.grants.length === 0 ? <p className="empty">No grants.</p> : (
        <table>
          <thead><tr><th>Effect</th><th>Person</th><th>Scope</th><th>Permissions</th><th>Window</th><th /></tr></thead>
          <tbody>
            {data.grants.map((g) => (
              <tr key={g.id} data-testid="grant-row" data-effect={g.effect}>
                <td><span className={`tag ${g.effect}`}>{g.effect}</span></td>
                <td>{person(g.userId)}</td>
                <td>{device(g.deviceId)}</td>
                <td>{g.permissions.join(', ')}</td>
                <td>{g.startsAt || g.expiresAt ? `${g.startsAt ?? '…'} → ${g.expiresAt ?? '…'}` : 'always'}</td>
                <td>
                  <Action set={perms} perm="grant:revoke" testid="revoke-grant" onClick={() => revoke(g)}>Revoke</Action>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </section>
  );
}

function NewGrant({ base, data, session, onDone }) {
  const others = data.members.filter((m) => m.userId !== session.user.id);
  const catalogue = Object.keys(session.permissions).sort();
  const [userId, setUserId] = useState(others[0]?.userId ?? '');
  const [deviceId, setDeviceId] = useState('');
  const [effect, setEffect] = useState('allow');
  const [picked, setPicked] = useState([]);
  const [expiresAt, setExpiresAt] = useState('');
  const run = useRun();

  const toggle = (p) => setPicked(picked.includes(p) ? picked.filter((x) => x !== p) : [...picked, p]);

  async function submit(e) {
    e.preventDefault();
    const made = await run(() => api('POST', `${base}/grants`, {
      userId,
      deviceId: deviceId || null,
      effect,
      permissions: picked,
      ...(expiresAt ? { expiresAt: new Date(expiresAt).toISOString() } : {}),
    }), 'Grant created.');
    if (made) onDone();
  }

  return (
    <form className="panel" onSubmit={submit}>
      <label>Person
        <select data-testid="grant-user" value={userId} onChange={(e) => setUserId(e.target.value)}>
          {others.map((m) => <option key={m.userId} value={m.userId}>{m.name} ({m.role})</option>)}
        </select>
      </label>
      <label>Scope
        <select data-testid="grant-device" value={deviceId} onChange={(e) => setDeviceId(e.target.value)}>
          <option value="">Whole org</option>
          {data.devices.map((d) => <option key={d.id} value={d.id}>{d.name}</option>)}
        </select>
      </label>
      <label>Effect
        <select data-testid="grant-effect" value={effect} onChange={(e) => setEffect(e.target.value)}>
          <option value="allow">allow</option>
          <option value="deny">deny</option>
        </select>
      </label>
      <div className="perms">
        {catalogue.map((p) => (
          <label key={p}>
            <input type="checkbox" data-permission-key={p} checked={picked.includes(p)} onChange={() => toggle(p)} />
            {p}
          </label>
        ))}
      </div>
      <label>Expires (optional)
        <input type="datetime-local" value={expiresAt} onChange={(e) => setExpiresAt(e.target.value)} />
      </label>
      <div><button type="submit" data-testid="grant-submit">Create grant</button></div>
    </form>
  );
}
