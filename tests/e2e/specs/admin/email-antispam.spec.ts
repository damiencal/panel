import { test, expect } from '@playwright/test';

test.describe('Admin Antispam', () => {
    test('antispam page loads', async ({ page }) => {
        await page.goto('/admin/antispam');
        await page.waitForLoadState('networkidle');

        await expect(page).not.toHaveURL(/login/);
        await expect(page.getByText(/antispam|spam/i).first()).toBeVisible({ timeout: 15_000 });
    });

    test('SpamAssassin or Rspamd toggle is visible', async ({ page }) => {
        await page.goto('/admin/antispam');
        await page.waitForLoadState('networkidle');

        const toggle = page
            .getByText(/spamassassin|rspamd/i)
            .or(page.getByRole('checkbox', { name: /spam/i }))
            .or(page.getByRole('switch', { name: /spam/i }))
            .first();
        await expect(toggle).toBeVisible({ timeout: 15_000 });
    });

    test('spam score threshold input is present', async ({ page }) => {
        await page.goto('/admin/antispam');
        await page.waitForLoadState('networkidle');

        // The label "Spam Score Threshold" is adjacent to a number input (no label-for association)
        // Check label text is visible, or find the number input directly
        const threshold = page
            .getByText(/spam score threshold/i)
            .or(page.locator('input[type="number"]').first());
        await expect(threshold.first()).toBeVisible({ timeout: 15_000 });
    });

    test('save settings button is present', async ({ page }) => {
        await page.goto('/admin/antispam');
        await page.waitForLoadState('networkidle');

        const save = page.getByRole('button', { name: /save|update|apply/i }).first();
        await expect(save).toBeVisible({ timeout: 15_000 });
    });
});
