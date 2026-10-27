import { expect, test, type Page } from '@playwright/test';
import { E2E_KEYS } from '../playwright.config';

// End-to-end analyst → approver workflow against the isolated stack defined in
// playwright.config.ts. All data is synthetic and every action is simulated.

async function signIn(page: Page, key: string, expectedName: string): Promise<void> {
  await page.goto('/');
  await page.getByLabel('API key').fill(key);
  await page.getByRole('button', { name: 'Sign in' }).click();
  await expect(page.getByText(`Signed in as ${expectedName}`)).toBeVisible();
}

async function nav(page: Page, name: string | RegExp): Promise<void> {
  await page.getByLabel('Primary').getByRole('link', { name }).click();
}

async function signOut(page: Page): Promise<void> {
  await page.getByRole('button', { name: 'Sign out' }).click();
  await expect(page.getByLabel('API key')).toBeVisible();
}

test('analyst proposes, approver approves and executes once, audit chain stays valid', async ({ page, request }) => {
  // 1–2. Open dashboard and sign in as analyst.
  await signIn(page, E2E_KEYS.analyst, 'e2e-analyst');

  // 3. Load the synthetic intrusion scenario.
  await nav(page, 'Alerts');
  const scenario = page.locator('li', { hasText: 'Multi-stage intrusion' });
  await scenario.getByRole('button', { name: /Load/ }).click();
  const banner = page.locator('.alert-box.ok', { hasText: 'Multi-stage intrusion' });
  await expect(banner).toContainText('6 new alert(s)');

  // 4. The alerts are visible in the list.
  await expect(page.getByRole('cell', { name: /Encoded PowerShell command line executed/ })).toBeVisible();
  await expect(page.getByRole('cell', { name: /Large outbound HTTPS transfer/ })).toBeVisible();

  // 5. Open the generated incident from the load result.
  const incidentLink = banner.locator('a[href^="#/incidents/"]').first();
  const incidentId = (await incidentLink.textContent())?.trim() ?? '';
  expect(incidentId).toMatch(/^INC-[0-9A-F]{8}$/);
  await incidentLink.click();
  await expect(page.getByText('Investigation workspace')).toBeVisible();

  // 6. Severity explanation and correlated entities.
  await expect(page.getByText('Risk explanation')).toBeVisible();
  await expect(page.getByText('attack progression')).toBeVisible();
  await expect(page.getByText('Correlated by same Wazuh agent ID 001').first()).toBeVisible();
  const entities = page.locator('section', { hasText: 'Affected entities' });
  await expect(entities.getByRole('link', { name: 'db-server-01' })).toBeVisible();
  await expect(entities.getByRole('link', { name: 'web-server-01' })).toBeVisible();

  // 7. Submit a simulated response action.
  await page.getByRole('tab', { name: /Response/ }).click();
  await page.locator('#an').selectOption('isolate_host');
  await page.locator('#at').selectOption('db-server-01');
  await page.locator('#ar').fill('E2E: contain host after large outbound transfer');
  await page.getByRole('button', { name: 'Submit for guardrail evaluation' }).click();
  await expect(page.getByText(/Guardrail: REQUIRE_APPROVAL/)).toBeVisible();

  // 8. The approval is pending and bound to this incident.
  const row = page.locator('tr', { hasText: 'isolate_host' });
  await expect(row).toContainText('PENDING');
  const requestId = ((await row.locator('.cell-sub').first().textContent()) ?? '').split('·')[0].trim();
  expect(requestId).toMatch(/^apr-[0-9a-f]{12}$/);

  // 9. The analyst cannot approve: no decision control in the UI, and the server refuses.
  await expect(row).toContainText('Approver role required');
  const analystDecide = await request.post(`/api/v1/approvals/${requestId}/decide`, {
    headers: { Authorization: `Bearer ${E2E_KEYS.analyst}` },
    data: { decision: 'APPROVE', reason: 'self approval attempt' },
  });
  expect(analystDecide.status()).toBe(403);

  // 10. Switch to the approver.
  await signOut(page);
  await signIn(page, E2E_KEYS.approver, 'e2e-approver');

  // 11. Approve the exact pending proposal.
  await nav(page, /Response Approvals/);
  const pending = page.locator('tr', { hasText: requestId });
  await expect(pending).toContainText('PENDING');
  await pending.getByRole('button', { name: 'Review…' }).click();
  await pending.getByLabel('Decision reason').fill('E2E: confirmed exfiltration path');
  await pending.getByRole('button', { name: 'Approve' }).click();

  // 12. Execute and verify the simulated result.
  await page.getByRole('button', { name: 'approved', exact: true }).click();
  const approved = page.locator('tr', { hasText: requestId });
  await expect(approved).toContainText('APPROVED');
  await approved.getByRole('button', { name: /Execute \(simulated\)/ }).click();
  await page.getByRole('button', { name: 'executed', exact: true }).click();
  const executed = page.locator('tr', { hasText: requestId });
  await expect(executed).toContainText('EXECUTED');
  await expect(executed).toContainText('executed (simulated)');

  // 13. Audit entries exist and the chain is intact.
  await nav(page, 'Audit Log');
  await expect(page.getByText(/Chain intact: \d+ events verified/)).toBeVisible();
  await expect(page.getByRole('cell', { name: 'simulated_action_executed' }).first()).toBeVisible();
  await expect(page.getByRole('cell', { name: 'human_approval_decision' }).first()).toBeVisible();

  // 14. The decided approval cannot be reused or reversed.
  const approverHeaders = { Authorization: `Bearer ${E2E_KEYS.approver}` };
  const replay = await request.post(`/api/v1/approvals/${requestId}/execute`, { headers: approverHeaders });
  expect(replay.status()).toBe(409);
  const reverse = await request.post(`/api/v1/approvals/${requestId}/decide`, {
    headers: approverHeaders,
    data: { decision: 'REJECT', reason: 'try to reverse' },
  });
  expect(reverse.status()).toBe(409);
  const final = await request.get(`/api/v1/approvals/${requestId}`, { headers: approverHeaders });
  expect((await final.json()).status).toBe('EXECUTED');
  const verify = await request.get('/api/v1/audit/verify', { headers: approverHeaders });
  expect((await verify.json()).verified).toBe(true);
});
