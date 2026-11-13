import { test, expect } from '@playwright/test';

const fixture = {
  target: 'test',
  kind: 'people',
  input_type: 'username',
  fetched_at: '2026-01-01T00:00:00Z',
  observations: [],
  accounts: [
    { id: 'account:github:test', platform: 'github', handle: 'test', url: 'https://github.com/test', sources: ['sherlock', 'maigret'], confidence_tier: 'high', multi_source: true, verified: true },
    { id: 'account:reddit:test', platform: 'reddit', handle: 'test', url: 'https://reddit.com/user/test', sources: ['sherlock'], confidence_tier: 'medium', multi_source: false, verified: true },
    { id: 'account:vk:test', platform: 'vk', handle: 'test', url: 'https://vk.com/test', sources: ['maigret'], confidence_tier: 'high', multi_source: false, verified: true },
  ],
  actor: {
    id: 'actor:test',
    label: 'test',
    confidence_tier: 'high',
    accounts: ['account:github:test', 'account:reddit:test', 'account:vk:test'],
  },
  breaches: [
    { name: 'ExampleBreach', date: '2024-01-01', data_classes: ['emails'], email: 'test@example.com' },
  ],
  phone: null,
  errors: [],
};

test('profile URL enriches account with public metadata', async ({ page }) => {
  const profileFixture = {
    target: 'https://vk.com/test',
    kind: 'people',
    input_type: 'profile_url',
    fetched_at: '2026-01-01T00:00:00Z',
    observations: [],
    accounts: [
      {
        id: 'account:vk:test',
        platform: 'vk',
        handle: 'test',
        url: 'https://vk.com/test',
        name: 'Test Profile',
        bio: 'Public bio from OpenGraph',
        avatar: 'https://cdn.example/avatar.jpg',
        links: ['https://t.me/test'],
        sources: ['profile', 'sherlock'],
        confidence_tier: 'high',
        multi_source: true,
        verified: true,
        score: 100,
        match_score: 100,
        match_reason: 'input profile',
      },
    ],
    actor: { id: 'actor:https://vk.com/test', label: 'Test Profile', confidence_tier: 'high', accounts: ['account:vk:test'] },
    breaches: [],
    phone: null,
    errors: [],
  };

  await page.addInitScript(() => localStorage.setItem('stare_token', 'e2e'));
  await page.route('**/api/people', route => route.fulfill({
    status: 200,
    contentType: 'application/json',
    body: JSON.stringify(profileFixture),
  }));

  await page.goto('/');
  await page.getByRole('button', { name: '[ EXECUTE ]' }).click();
  await page.locator('.terminal-input').fill('https://vk.com/test');
  await page.getByRole('button', { name: '[ EXECUTE ]' }).click();

  await page.waitForFunction(
    () => window.__cy && window.__cy.nodes().filter(n => n.data('type') === 'account').length >= 1,
    null,
    { timeout: 60000 }
  );

  const label = await page.evaluate(() => window.__cy.nodes().filter(n => n.data('type') === 'account').first().data('label'));
  expect(label).toContain('Test Profile');

  const pos = await page.evaluate(() => {
    const cy = window.__cy;
    const node = cy.nodes().filter(n => n.data('type') === 'account').first();
    cy.nodes().forEach(n => n.style('display', n.id() === node.id() ? 'element' : 'none'));
    cy.edges().style('display', 'none');
    cy.center(node);
    const p = node.renderedPosition();
    return { x: p.x, y: p.y };
  });
  await page.waitForTimeout(300);
  const box = await page.locator('.graph-container').boundingBox();
  await page.mouse.click(box.x + pos.x, box.y + pos.y);

  const panel = page.locator('.node-details-panel');
  await expect(panel).toContainText('Test Profile');
  await expect(panel).toContainText('Public bio');
});

test('username investigation renders accounts and details', async ({ page }) => {
  await page.addInitScript(() => localStorage.setItem('stare_token', 'e2e'));
  await page.route('**/api/people', route => route.fulfill({
    status: 200,
    contentType: 'application/json',
    body: JSON.stringify(fixture),
  }));

  await page.goto('/');
  await page.getByRole('button', { name: '[ EXECUTE ]' }).click();
  await page.locator('.terminal-input').fill('test');
  await page.getByRole('button', { name: '[ EXECUTE ]' }).click();

  await page.waitForFunction(
    () => window.__cy && window.__cy.nodes().filter(n => n.data('type') === 'account').length >= 3,
    null,
    { timeout: 60000 }
  );

  const accounts = await page.evaluate(() => window.__cy.nodes().filter(n => n.data('type') === 'account').length);
  expect(accounts).toBeGreaterThanOrEqual(3);

  const pos = await page.evaluate(() => {
    const cy = window.__cy;
    const node = cy.nodes().filter(n => n.data('type') === 'account').first();
    cy.nodes().forEach(n => n.style('display', n.id() === node.id() ? 'element' : 'none'));
    cy.edges().style('display', 'none');
    cy.center(node);
    const p = node.renderedPosition();
    return { x: p.x, y: p.y };
  });
  await page.waitForTimeout(300);
  const box = await page.locator('.graph-container').boundingBox();
  await page.mouse.click(box.x + pos.x, box.y + pos.y);

  const panel = page.locator('.node-details-panel');
  await expect(panel).toContainText(/account/i);
  await expect(panel).toContainText(/source/i);
  await expect(panel).toContainText(/confidence/i);
});
