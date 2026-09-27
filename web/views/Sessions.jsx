// Sessions. A running session can show here while the device row has no button for
// it: the session runs on its snapshot, the button on today's permissions (PERMISSIONS §7).

import React, { useState } from 'react';
import { api } from '../api.js';
import { Action, allowed, useLoad, useRun } from '../ui.jsx';

const MODES = ['view', 'control', 'terminal'];

export function Sessions({ session }) {
  const base = `/orgs/${session.orgId}`;
  const perms = session.permissions;
  const [data, reload] = useLoad(() =>
    Promise.all([
      api('GET', `${base}/sessions`),
      allowed(perms, 'device:list') ? api('GET', `${base}/devices`) : { devices: [] },
    ]).then(([s, d]) => ({ sessions: s.sessions, devices: d.devices })));
  const [starting, setStarting] = useState(false);
  const run = useRun();

  if (!data) return <p className="empty">Loading sessions…</p>;
  const device = (id) => data.devices.find((d) => d.id === id)?.name ?? 'a device you cannot see';

  async function stop(s) {
    await run(() => api('DELETE', `/sessions/${s.id}`), 'Session ended.');
    reload();
  }

  return (
    <section>
      <div className="toolbar">
        <h2>Sessions</h2>
        <Action set={perms} perm="session:start" testid="new-session" onClick={() => setStarting(!starting)}>+ Start a session</Action>
      </div>

      {starting && <StartSession base={base} devices={data.devices} onDone={() => { setStarting(false); reload(); }} />}

      {data.sessions.length === 0 ? <p className="empty">No sessions.</p> : (
        <table>
          <thead><tr><th>Device</th><th>Mode</th><th>Who</th><th>State</th><th>Started</th><th>Ends</th><th /></tr></thead>
          <tbody>
            {data.sessions.map((s) => {
              const mine = s.user_id === session.user.id;
              const live = s.state !== 'ended';
              return (
                <tr key={s.id} data-testid="session-row" data-session-id={s.id}>
                  <td>{device(s.device_id)}</td>
                  <td>{s.mode}</td>
                  <td>{mine ? 'you' : s.user_id}</td>
                  <td>{s.state}{s.end_reason && ` (${s.end_reason})`}</td>
                  <td>{new Date(s.started_at).toLocaleString()}</td>
                  <td>{new Date(s.ended_at ?? s.expires_at).toLocaleString()}</td>
                  <td>
                    {live && mine && (
                      <button type="button" data-testid="stop-session" data-state="unlocked" onClick={() => stop(s)}>Stop</button>
                    )}
                    {live && !mine && (
                      <Action set={perms} perm="session:terminate" testid="stop-session" onClick={() => stop(s)}>Stop</Action>
                    )}
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      )}
    </section>
  );
}

// Whether this person may start on this device is the server's call: a refusal comes
// back with a reason that says which of the two permissions was missing.
function StartSession({ base, devices, onDone }) {
  const [deviceId, setDeviceId] = useState(devices[0]?.id ?? '');
  const [mode, setMode] = useState('view');
  const run = useRun();

  async function submit(e) {
    e.preventDefault();
    const made = await run(() => api('POST', `${base}/sessions`, { deviceId, mode }), 'Session started.');
    if (made) onDone();
  }

  return (
    <form className="panel" onSubmit={submit}>
      <label>Device
        <select value={deviceId} onChange={(e) => setDeviceId(e.target.value)}>
          {devices.map((d) => <option key={d.id} value={d.id}>{d.name}</option>)}
        </select>
      </label>
      <label>Mode
        <select value={mode} onChange={(e) => setMode(e.target.value)}>
          {MODES.map((m) => <option key={m}>{m}</option>)}
        </select>
      </label>
      <div><button type="submit">Start</button></div>
    </form>
  );
}
