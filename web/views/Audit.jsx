// Audit: the newest 100 events in this org, denials included.

import React from 'react';
import { api } from '../api.js';
import { useLoad } from '../ui.jsx';

export function Audit({ session }) {
  const [events] = useLoad(() => api('GET', `/orgs/${session.orgId}/audit?limit=100`).then((b) => b.events));
  if (!events) return <p className="empty">Loading audit log…</p>;

  return (
    <section>
      <h2>Audit</h2>
      {events.length === 0 ? <p className="empty">Nothing recorded yet.</p> : (
        <table>
          <thead><tr><th>When</th><th>Who</th><th>Action</th><th>Target</th><th>Result</th><th>Reason</th></tr></thead>
          <tbody>
            {events.map((e) => (
              <tr key={e.id} data-testid="audit-row" data-result={e.result}>
                <td>{new Date(e.at).toLocaleString()}</td>
                <td>{e.actor_id}</td>
                <td>{e.action}</td>
                <td>{e.target_type} {e.target_id}</td>
                <td><span className={`tag ${e.result}`}>{e.result}</span></td>
                <td>{e.reason_code}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </section>
  );
}
