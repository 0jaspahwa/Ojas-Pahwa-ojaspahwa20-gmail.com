// The "why?" inspector: the endpoint's gates, and the panel's plain-English trace.
// The proof that the trace cannot drift from the real decision is scripts/probe-explain.js.

import { test, expect } from '@playwright/test';

async function login(page, email) {
  await page.goto('/');
  await page.getByTestId('login-email').fill(email);
  await page.getByTestId('login-password').fill('demo1234');
  await page.getByTestId('login-submit').click();
  await expect(page.getByTestId('app-shell')).toBeVisible();
}

async function tokenFor(request, email) {
  const res = await request.post('/v1/auth/login', { data: { email, password: 'demo1234' } });
  return (await res.json()).token;
}

test('explain endpoint: same gate as /effective', async ({ request }) => {
  const get = async (email, path) =>
    (await request.get(`/v1${path}`, { headers: { authorization: `Bearer ${await tokenFor(request, email)}` } })).status();

  expect(await get('dana@example.test', '/orgs/org_acme/users/usr_sam/explain?permission=device:terminal')).toBe(200);
  expect(await get('sam@example.test', '/orgs/org_acme/users/usr_sam/explain?permission=device:terminal')).toBe(200);    // yourself
  expect(await get('sam@example.test', '/orgs/org_acme/users/usr_dana/explain?permission=device:terminal')).toBe(403);   // no user:read
  expect(await get('dana@example.test', '/orgs/org_acme/users/usr_globex_owner/explain?permission=device:view')).toBe(404);
  expect(await get('dana@example.test', '/orgs/org_acme/users/usr_sam/explain?permission=device:view&deviceId=dev_globex_desk_01')).toBe(404);
  expect(await get('dana@example.test', '/orgs/org_acme/users/usr_sam/explain?permission=device:teleport')).toBe(400);
});

test('People: why is the viewer missing kiosk-lobby-01?', async ({ page }) => {
  await login(page, 'dana@example.test');
  await page.getByTestId('nav-people').click();
  const panel = page.getByTestId('why-panel');
  await panel.getByTestId('why-user').selectOption('usr_acme_viewer');
  await panel.getByTestId('why-permission').selectOption('device:view');
  await panel.getByTestId('why-device').selectOption('dev_kiosk_lobby_01');
  await panel.getByTestId('why-submit').click();

  await expect(page.getByTestId('why-decision')).toHaveAttribute('data-effect', 'deny');
  await expect(page.getByTestId('why-step')).toContainText([
    'Active member with the viewer role.',
    'Grant grt_viewer_deny_kiosk (deny device:view, on kiosk-lobby-01) applies.',
    'Denied by grant grt_viewer_deny_kiosk. A deny always wins, whatever else allows it.',
  ]);
});

test('People: a device deny is skipped at org level', async ({ page }) => {
  await login(page, 'dana@example.test');
  await page.getByTestId('nav-people').click();
  const panel = page.getByTestId('why-panel');
  await panel.getByTestId('why-user').selectOption('usr_acme_viewer');
  await panel.getByTestId('why-permission').selectOption('device:view');
  await panel.getByTestId('why-submit').click();

  await expect(page.getByTestId('why-decision')).toHaveAttribute('data-effect', 'allow');
  await expect(page.getByTestId('why-step').filter({ hasText: 'grt_viewer_deny_kiosk' }))
    .toContainText('skipped: a deny on one device does not remove it org-wide.');
});

test('My access: open to everyone, about yourself only', async ({ page }) => {
  await login(page, 'sam@example.test');   // operator: no People card
  await expect(page.getByTestId('nav-people')).toHaveCount(0);
  await page.getByTestId('my-access').click();
  await expect(page.getByTestId('why-user')).toHaveCount(0);

  await page.getByTestId('why-permission').selectOption('device:terminal');
  await page.getByTestId('why-submit').click();
  await expect(page.getByTestId('why-decision')).toHaveAttribute('data-effect', 'deny');
  await expect(page.getByTestId('why-step').last()).toContainText('Denied by grant grt_sam_deny_terminal_orgwide');

  await page.getByTestId('why-permission').selectOption('audit:read');
  await page.getByTestId('why-submit').click();
  await expect(page.getByTestId('why-step')).toContainText(['No grant mentions this permission.',
    'The operator role does not include audit:read.', 'Nobody granted this, so it is denied.']);
});

test('My access is not a nav-* card: an owner still has exactly six', async ({ page }) => {
  await login(page, 'dana@example.test');
  await expect(page.locator('[data-testid^="nav-"]')).toHaveCount(6);
  await expect(page.getByTestId('my-access')).toHaveCount(1);
});
