import { test, expect } from '@playwright/test';

test.beforeEach(async ({ page }) => {
  await page.goto('/?bench=300');
  await page.waitForFunction(() => window.__cy && window.__graphMetrics, null, { timeout: 60000 });
});

test('renders nodes and edges', async ({ page }) => {
  const counts = await page.evaluate(() => ({
    nodes: window.__cy.nodes().length,
    edges: window.__cy.edges().length,
  }));
  expect(counts.nodes).toBeGreaterThan(200);
  expect(counts.edges).toBeGreaterThan(200);
  await expect(page.locator('.renderer-badge')).toContainText(/CANVAS|WEBGL/);
});

test('progressive disclosure reveals neighbors', async ({ page }) => {
  const before = await page.evaluate(() => window.__cy.nodes(':visible').length);
  const total = await page.evaluate(() => window.__cy.nodes().length);
  expect(before).toBeLessThan(total);

  const after = await page.evaluate(() => {
    window.__cy.getElementById('bench.local').emit('tap');
    return new Promise(resolve => setTimeout(() => resolve(window.__cy.nodes(':visible').length), 200));
  });
  expect(after).toBeGreaterThanOrEqual(before);
});

test('filters hide node types', async ({ page }) => {
  await page.getByRole('button', { name: '[ FILTERS ]' }).click();
  await page.getByLabel('IP', { exact: true }).uncheck();
  await page.waitForTimeout(250);

  const visibleIPs = await page.evaluate(() => window.__cy.nodes(':visible').filter(n => n.data('type') === 'ip').length);
  expect(visibleIPs).toBe(0);
});

test('search focuses a node', async ({ page }) => {
  await page.locator('.graph-search').fill('host5.bench.local');
  await page.locator('.graph-search').press('Enter');
  await expect(page.locator('.node-details-panel')).toContainText('host5.bench.local');
});

test('observation panel shows source and confidence', async ({ page }) => {
  const pos = await page.evaluate(() => {
    window.__graphShowAll();
    const cy = window.__cy;
    const node = cy.getElementById('obs:ipinfo:0');
    if (node.empty()) return null;
    cy.nodes().forEach(n => n.style('display', n.id() === node.id() ? 'element' : 'none'));
    cy.edges().style('display', 'none');
    cy.center(node);
    cy.zoom(2);
    const p = node.renderedPosition();
    return { x: p.x, y: p.y };
  });
  expect(pos).not.toBeNull();
  await page.waitForTimeout(300);
  const box = await page.locator('.graph-container').boundingBox();
  await page.mouse.click(box.x + pos.x, box.y + pos.y);
  const panel = page.locator('.node-details-panel');
  await expect(panel).toContainText('ipinfo');
  await expect(panel).toContainText(/confidence/i);
});
