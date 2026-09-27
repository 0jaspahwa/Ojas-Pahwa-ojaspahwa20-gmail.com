// Route registration. The router is deliberately tiny: createRouter() from
// ../router.js, first match wins, so register specific paths before parameterised
// ones ('/members/me' before '/members/:userId').
//
// Every endpoint is in BRIEF.md §5.1; the response shapes the console reads are in §5.2.

import { registerAuthRoutes } from './auth.js';
import { registerDeviceRoutes } from './devices.js';
import { registerSessionRoutes } from './sessions.js';

export function registerRoutes(router, deps) {
  registerAuthRoutes(router, deps);
  registerDeviceRoutes(router, deps);
  registerSessionRoutes(router, deps);
}
