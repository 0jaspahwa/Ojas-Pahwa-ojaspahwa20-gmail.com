// The "why?" inspector. Asks the server to explain one decision and shows its trace in
// words. The trace comes from the same decide() that answers every real request, so
// what this panel says is what the server did.

import React, { useState } from 'react';
import { api } from '../api.js';
import { allowed, useLoad, useRun } from '../ui.jsx';

// `members` given: pick anyone (People card). Not given: yourself only (My access).
export function Why({ session, members }) {
  const base = `/orgs/${session.orgId}`;
  const [devices] = useLoad(() =>
    allowed(session.permissions, 'device:list') ? api('GET', `${base}/devices`).then((b) => b.devices) : Promise.resolve([]));
  const catalogue = Object.keys(session.permissions).sort();
  const [userId, setUserId] = useState(members ? members[0]?.userId : session.user.id);
  const [permission, setPermission] = useState(catalogue[0]);
  const [deviceId, setDeviceId] = useState('');
  const [answer, setAnswer] = useState(null);
  const run = useRun();

  async function ask(e) {
    e.preventDefault();
    const q = new URLSearchParams({ permission, ...(deviceId ? { deviceId } : {}) });
    setAnswer(await run(() => api('GET', `${base}/users/${userId}/explain?${q}`)) ?? null);
  }

  const deviceName = (id) => devices?.find((d) => d.id === id)?.name ?? 'a device you cannot see';

  return (
    <section className="why" data-testid="why-panel">
      <h3>Why?</h3>
      <form className="panel" onSubmit={ask}>
        {members && (
          <label>Person
            <select data-testid="why-user" value={userId} onChange={(e) => setUserId(e.target.value)}>
              {members.map((m) => <option key={m.userId} value={m.userId}>{m.name}</option>)}
            </select>
          </label>
        )}
        <label>Permission
          <select data-testid="why-permission" value={permission} onChange={(e) => setPermission(e.target.value)}>
            {catalogue.map((p) => <option key={p}>{p}</option>)}
          </select>
        </label>
        <label>Device
          <select data-testid="why-device" value={deviceId} onChange={(e) => setDeviceId(e.target.value)}>
            <option value="">Org level (any device)</option>
            {(devices ?? []).map((d) => <option key={d.id} value={d.id}>{d.name}</option>)}
          </select>
        </label>
        <div><button type="submit" data-testid="why-submit">Explain</button></div>
      </form>

      {answer && (
        <div className="answer">
          <p data-testid="why-decision" data-effect={answer.decision.effect}>
            <span className={`tag ${answer.decision.effect}`}>{answer.decision.effect}</span>{' '}
            {headline(answer.decision)}
          </p>
          <ol>
            {steps(answer, deviceName).map((text, i) => <li key={i} data-testid="why-step">{text}</li>)}
          </ol>
        </div>
      )}
    </section>
  );
}

const grantOf = (source) => source?.replace(/^grant:/, '');

function headline({ effect, source, reason }) {
  if (effect === 'allow') {
    return source.startsWith('role:') ? `Allowed: the ${source.slice(5)} role includes it.` : `Allowed by grant ${grantOf(source)}.`;
  }
  if (reason === 'explicit_deny') return `Denied by grant ${grantOf(source)}.`;
  if (reason === 'suspended') return 'Denied: this membership is suspended.';
  if (reason === 'not_a_member') return 'Denied: not an active member of this organization.';
  return 'Nobody granted this.';
}

// One plain sentence per trace step, in the order the server took them.
function steps({ permission, deviceId, trace }, deviceName) {
  const out = [];
  for (const s of trace) {
    if (s.step === 'membership') {
      out.push(s.result === 'active' ? `Active member with the ${s.role} role.`
        : s.result === 'suspended' ? 'The membership is suspended, so every permission is denied.'
        : 'Not an active member here, so every permission is denied.');
    } else if (s.step === 'grants') {
      if (s.considered.length === 0) out.push('No grant mentions this permission.');
      for (const c of s.considered) {
        const label = `Grant ${c.grant} (${c.effect} ${c.pattern}, ${c.deviceId ? `on ${deviceName(c.deviceId)}` : 'org-wide'})`;
        if (c.applies) out.push(`${label} applies.`);
        else if (c.window === 'expired') out.push(`${label} skipped: it has expired.`);
        else if (c.window === 'not_started') out.push(`${label} skipped: it has not started yet.`);
        else if (c.window === 'invalid') out.push(`${label} skipped: its time window cannot be read.`);
        else if (deviceId === null && c.effect === 'deny') out.push(`${label} skipped: a deny on one device does not remove it org-wide.`);
        else out.push(`${label} skipped: it is for another device.`);
      }
    } else if (s.step === 'deny_wins') {
      out.push(`Denied by grant ${s.grant}. A deny always wins, whatever else allows it.`);
    } else if (s.step === 'baseline') {
      out.push(`The ${s.role} role ${s.contains ? 'includes' : 'does not include'} ${permission}.`);
    } else if (s.step === 'allow_grant') {
      out.push(`Allowed by grant ${s.grant}.`);
    } else if (s.step === 'implicit_deny') {
      out.push('Nobody granted this, so it is denied.');
    }
  }
  return out;
}
