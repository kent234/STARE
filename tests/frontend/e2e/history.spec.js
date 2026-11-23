import { test, expect } from '@playwright/test';

const SCANS = [
  { id: '11111111-1111-1111-1111-111111111111', target: 'one.example', created_at: '2026-01-01T10:00:00Z' },
  { id: '22222222-2222-2222-2222-222222222222', target: 'two.example', created_at: '2026-01-02T10:00:00Z' },
  { id: '33333333-3333-3333-3333-333333333333', target: 'three.example', created_at: '2026-01-03T10:00:00Z' },
];

// Сохранённая история живёт в Postgres на бэкенде, поэтому в e2e
// подменяем только /api/scans и /api/scans/delete, а UI проверяем настоящий.
async function openMainScreen(page) {
  await page.addInitScript(() => localStorage.setItem('stare_token', 'e2e'));
  await page.goto('/');
  await page.getByRole('button', { name: '[ EXECUTE ]' }).click();
  await expect(page.locator('.history-item')).toHaveCount(SCANS.length);
}

test('bulk delete and delete-all saved graphs', async ({ page }) => {
  const bulkRequests = [];

  await page.route('**/api/scans', async route => {
    if (route.request().method() !== 'GET') return route.fallback();
    return route.fulfill({
      status: 200,
      contentType: 'application/json',
      body: JSON.stringify(SCANS),
    });
  });

  await page.route('**/api/scans/delete', async route => {
    const payload = route.request().postDataJSON();
    bulkRequests.push(payload);
    const deleted = payload.all ? SCANS.length : payload.ids.length;
    return route.fulfill({
      status: 200,
      contentType: 'application/json',
      body: JSON.stringify({ deleted }),
    });
  });

  page.on('dialog', dialog => dialog.accept());
  await openMainScreen(page);

  // Выбираем два скана чекбоксами: кнопка должна показать их количество.
  await page.getByLabel(`Select ${SCANS[0].target}`).check();
  await page.getByLabel(`Select ${SCANS[1].target}`).check();
  await expect(page.locator('.history-item.selected')).toHaveCount(2);
  await expect(page.getByRole('button', { name: 'DEL 2' })).toBeVisible();

  await page.getByRole('button', { name: 'DEL 2' }).click();
  await expect(page.locator('.history-item')).toHaveCount(1);
  expect(bulkRequests[0]).toEqual({ ids: [SCANS[0].id, SCANS[1].id] });

  // «Удалить всё» очищает оставшуюся историю и текущий граф.
  await expect(page.getByRole('button', { name: 'DEL.ALL' })).toBeVisible();
  await page.getByRole('button', { name: 'DEL.ALL' }).click();
  await expect(page.locator('.history-item')).toHaveCount(0);
  await expect(page.locator('.history-list')).toContainText('No history yet');
  expect(bulkRequests[1]).toEqual({ all: true });
});
