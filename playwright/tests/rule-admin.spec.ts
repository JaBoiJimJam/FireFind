import { test, expect } from '@playwright/test';

const RULE_LABEL = 'Administrative port exposure';

test.describe('Admin rule management E2E', () => {
  test('allows creating, persisting, and deleting rule definitions', async ({ page }) => {
    await page.goto('/admin.html');

    await page.getByRole('button', { name: /Add Rule Definition/i }).click();

    const card = page.locator('.rule-logic-card').first();
    await expect(card).toBeVisible();

    await card.getByRole('button', { name: /Edit/i }).click();

    const modal = page.locator('[data-component="rule-editor"]');
    await expect(modal).toBeVisible();

    await modal.getByLabel('Rule identifier').fill('admin_port_exposed');
    await modal.getByLabel('Rule ID').fill('admin_port_exposed');
    await modal.getByLabel('Label').fill(RULE_LABEL);

    await modal.getByRole('button', { name: /Add condition/i }).click();
    await modal.getByPlaceholder('Field').fill('action');
    await modal.getByPlaceholder('Value').fill('allow');

    await modal.getByLabel('Analyzer key').fill('admin_port_exposed');

    await modal.getByRole('button', { name: /Save rule/i }).click();
    await expect(modal).toBeHidden();

    await expect(card.getByText(RULE_LABEL)).toBeVisible();

    await page.reload();
    const persistedCard = page.locator('.rule-logic-card');
    await expect(persistedCard).toHaveCount(1);
    await expect(persistedCard.getByText(RULE_LABEL)).toBeVisible();

    await persistedCard.getByRole('button', { name: new RegExp(`Delete ${RULE_LABEL}`, 'i') }).click();
    await expect(page.locator('.empty-state')).toBeVisible();
  });
});
