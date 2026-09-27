// The console. Two pages: /invite/:token, and everything else.
//
// No role-to-permission table lives in web/. Every element that depends on a permission
// reads a set the server resolved (UI-INVENTORY.md).

import React, { useEffect, useState } from 'react';
import { createRoot } from 'react-dom/client';
import { onSession, refresh } from './api.js';
import { Login } from './Login.jsx';
import { Shell } from './Shell.jsx';
import './styles.css';

function Console({ restore = true, notice }) {
  // undefined: still asking the refresh cookie; null: signed out.
  const [session, setSession] = useState(restore ? undefined : null);

  useEffect(() => {
    onSession(setSession);
    if (restore) refresh().catch(() => {}); // no cookie is normal: show the login form
  }, [restore]);

  if (session === undefined) return <p className="restoring">Restoring your session…</p>;
  if (!session) return <Login notice={notice} />;
  // Keyed by org: switching orgs unmounts everything from the old org.
  return <Shell key={session.orgId} session={session} />;
}

function App() {
  const [page, setPage] = useState(() => {
    const m = location.pathname.match(/^\/invite\/([^/]+)$/);
    return m ? { invite: decodeURIComponent(m[1]) } : {};
  });

  return <Console restore={!page.notice} notice={page.notice} />;
}

createRoot(document.getElementById('root')).render(<App />);
