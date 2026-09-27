// Small shared pieces: the permission-gated button, loading, and error reporting.

import React, { createContext, useCallback, useContext, useEffect, useState } from 'react';

// Present or absent, never disabled. `set` is a resolved permission set from the server:
// the org-level one from /auth/me, or a device row's own. The console decides nothing.
export function Action({ set, perm, testid, children, ...rest }) {
  if (set?.[perm]?.effect !== 'allow') return null;
  return (
    <button type="button" data-testid={testid} data-permission={perm} data-state="unlocked" {...rest}>
      {children}
    </button>
  );
}

export const allowed = (set, perm) => set?.[perm]?.effect === 'allow';

// --- messages ------------------------------------------------------------------------

const Report = createContext({ error: () => {}, info: () => {} });
export const useReport = () => useContext(Report);

// One line at the top of the shell. Errors carry the server's own words and code.
export function Messages({ children }) {
  const [msg, setMsg] = useState(null);
  const error = useCallback((err) => setMsg({ kind: 'error', text: err.message, code: err.code }), []);
  const info = useCallback((text) => setMsg({ kind: 'info', text }), []);
  return (
    <Report.Provider value={{ error, info }}>
      {msg && (
        <div
          className={`message ${msg.kind}`}
          data-testid={msg.kind === 'error' ? 'request-error' : 'request-info'}
          data-error-code={msg.code}
          role={msg.kind === 'error' ? 'alert' : 'status'}
        >
          <span>{msg.text}{msg.code && <code>{msg.code}</code>}</span>
          <button type="button" className="link" onClick={() => setMsg(null)}>Dismiss</button>
        </div>
      )}
      {children}
    </Report.Provider>
  );
}

// Load on mount (so every view refetches when it is opened), with a reload function.
export function useLoad(load) {
  const { error } = useReport();
  const [data, setData] = useState(null);
  const reload = useCallback(() => load().then(setData).catch(error), []); // eslint-disable-line react-hooks/exhaustive-deps
  useEffect(() => { reload(); }, [reload]);
  return [data, reload];
}

// Run an action; report failure on screen, report success if a message is given.
export function useRun() {
  const { error, info } = useReport();
  return async (fn, done) => {
    try {
      const out = await fn();
      if (done) info(typeof done === 'function' ? done(out) : done);
      return out;
    } catch (err) {
      error(err);
      return undefined;
    }
  };
}
