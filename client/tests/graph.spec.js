import { test, expect } from '@playwright/test';
import fs from 'node:fs';
import path from 'node:path';

const readMetrics = (page) => page.evaluate(() => {
  const m = window.__graphMetrics;
  return {
    initMs: m.initMs,
    nodes: m.nodes,
    edges: m.edges,
    domNodes: m.domNodes,
    canvas: m.canvas,
    renderer: m.renderer,
    idleFps: m.fpsHistory.length ? m.fpsHistory[m.fpsHistory.length - 1] : 0,
    lastFilterMs: m.lastFilterMs,
  };
});

test('graph benchmark 5000 nodes', async ({ page }) => {
  test.setTimeout(180000);
  await page.goto('/?bench=5000');
  await page.waitForFunction(() => window.__graphMetrics && window.__cy, null, { timeout: 120000 });
  await page.evaluate(() => window.__graphShowAll?.());
  await page.waitForTimeout(3000);
  const full = await readMetrics(page);

  const fullDragFps = await page.evaluate(() => window.__benchDrag(2000));
  const noEdgesDragFps = await page.evaluate(async () => {
    const cy = window.__cy;
    cy.edges().style('display', 'none');
    try {
      return await window.__benchDrag(2000);
    } finally {
      cy.edges().style('display', 'element');
    }
  });
  const filterMs = await page.evaluate(() => window.__graphFilterBench((d) => d.type !== 'ip'));
  await page.evaluate(() => window.__graphFilterBench(() => true));

  // Второй заход: progressive disclosure по умолчанию (1 hop).
  await page.goto('/?bench=5000');
  await page.waitForFunction(() => window.__graphMetrics && window.__cy, null, { timeout: 120000 });
  await page.waitForTimeout(2500);
  const defaultView = await page.evaluate(() => ({
    visibleNodes: window.__cy.nodes(':visible').length,
    visibleEdges: window.__cy.edges(':visible').length,
  }));
  const defaultDragFps = await page.evaluate(() => window.__benchDrag(2000));

  const result = {
    ...full,
    fullDragFps: Math.round(fullDragFps),
    noEdgesDragFps: Math.round(noEdgesDragFps),
    defaultVisibleNodes: defaultView.visibleNodes,
    defaultVisibleEdges: defaultView.visibleEdges,
    defaultDragFps: Math.round(defaultDragFps),
    fullFilterMs: Math.round(filterMs),
  };

  fs.mkdirSync(path.join(process.cwd(), 'bench'), { recursive: true });
  fs.writeFileSync(
    path.join(process.cwd(), 'bench', process.env.BENCH_OUT || 'last-run.json'),
    JSON.stringify(result, null, 2)
  );
  console.log('BENCH_RESULT', JSON.stringify(result));

  expect(result.nodes).toBeGreaterThan(4000);
  expect(result.edges).toBeGreaterThan(4000);
  expect(result.defaultDragFps).toBeGreaterThan(30);
});
