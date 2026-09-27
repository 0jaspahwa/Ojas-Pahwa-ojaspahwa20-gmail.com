// Devices. Row buttons come from each row's own resolved set (device-scoped grants and
// denies show up here); "Add device" from the org-level set.

import React, { useState } from 'react';
import { api } from '../api.js';
import { Action, useLoad, useRun } from '../ui.jsx';

const KINDS = ['linux', 'macos', 'windows', 'android', 'ios'];

export function Devices({ session }) {
  const base = `/orgs/${session.orgId}/devices`;
  const [devices, reload] = useLoad(() => api('GET', base).then((b) => b.devices));
  const [adding, setAdding] = useState(false);
  const run = useRun();

  const start = (d, mode) =>
    run(() => api('POST', `/orgs/${session.orgId}/sessions`, { deviceId: d.id, mode }),
        `Started a ${mode} session on ${d.name}.`);

  async function rename(d) {
    const name = window.prompt(`New name for ${d.name}`, d.name);
    if (!name?.trim() || name.trim() === d.name) return;
    await run(() => api('PATCH', `${base}/${d.id}`, { name: name.trim() }), `Renamed to ${name.trim()}.`);
    reload();
  }

  async function decommission(d) {
    if (!window.confirm(`Decommission ${d.name}? Its sessions end and it leaves the list.`)) return;
    await run(() => api('DELETE', `${base}/${d.id}`), `${d.name} was decommissioned.`);
    reload();
  }

  if (!devices) return <p className="empty">Loading devices…</p>;

  return (
    <section>
      <div className="toolbar">
        <h2>Devices</h2>
        <Action set={session.permissions} perm="device:provision" testid="add-device" onClick={() => setAdding(!adding)}>
          + Add device
        </Action>
      </div>

      {adding && <AddDevice base={base} onDone={() => { setAdding(false); reload(); }} />}

      {devices.length === 0 ? (
        <p className="empty" data-testid="devices-empty">No devices in this organization yet.</p>
      ) : (
        <table>
          <thead><tr><th>Name</th><th>Kind</th><th>Status</th><th>Actions</th></tr></thead>
          <tbody>
            {devices.map((d) => (
              <tr key={d.id} data-testid="device-row" data-device-id={d.id}>
                <td>{d.name}</td>
                <td>{d.kind}</td>
                <td><span className={`dot ${d.online ? 'on' : ''}`} />{d.online ? 'online' : 'offline'}</td>
                <td className="actions">
                  <Action set={d.permissions} perm="device:view" testid="start-view" onClick={() => start(d, 'view')}>View</Action>
                  <Action set={d.permissions} perm="device:control" testid="start-control" onClick={() => start(d, 'control')}>Control</Action>
                  <Action set={d.permissions} perm="device:terminal" testid="start-terminal" onClick={() => start(d, 'terminal')}>Terminal</Action>
                  <Action set={d.permissions} perm="device:file_transfer" testid="transfer-files"
                          onClick={() => run(async () => {}, 'File transfer runs in the device agent, which this console does not include.')}>
                    Files
                  </Action>
                  <Action set={d.permissions} perm="device:update" testid="rename-device" onClick={() => rename(d)}>Rename</Action>
                  <Action set={d.permissions} perm="device:provision" testid="decommission-device" className="danger" onClick={() => decommission(d)}>
                    Decommission
                  </Action>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </section>
  );
}

function AddDevice({ base, onDone }) {
  const [name, setName] = useState('');
  const [kind, setKind] = useState(KINDS[0]);
  const run = useRun();

  async function submit(e) {
    e.preventDefault();
    const made = await run(() => api('POST', base, { name, kind }), (d) => `Added ${d.name}.`);
    if (made) onDone();
  }

  return (
    <form className="panel" onSubmit={submit}>
      <label>Name <input value={name} onChange={(e) => setName(e.target.value)} required /></label>
      <label>Kind
        <select value={kind} onChange={(e) => setKind(e.target.value)}>
          {KINDS.map((k) => <option key={k}>{k}</option>)}
        </select>
      </label>
      <div><button type="submit">Add</button></div>
    </form>
  );
}
