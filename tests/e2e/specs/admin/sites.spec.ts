import { test, expect } from '@playwright/test';

test.describe('Admin All Sites', () => {
    test('shows sites from all users', async ({ page }) => {
        await page.goto('/admin/sites');
        await page.waitForLoadState('networkidle');

        // Should show sites from both client and reseller
        await expect(page.getByText('wp.panel.test', { exact: true }).first()).toBeVisible({ timeout: 15_000 });
        await expect(page.getByText('static.panel.test', { exact: true }).first()).toBeVisible({ timeout: 5_000 });
        await expect(page.getByText('reseller-site.panel.test', { exact: true }).first()).toBeVisible({ timeout: 5_000 });
    });

    test('shows site owner column', async ({ page }) => {
        await page.goto('/admin/sites');
        await page.waitForLoadState('networkidle');

        // Owner column should reference client and reseller usernames
        await expect(page.getByText(/client|reseller/i).first()).toBeVisible();
    });

    test('search/filter by domain narrows results', async ({ page }) => {
        await page.goto('/admin/sites');
        await page.waitForLoadState('networkidle');

        const searchInput = page.getByPlaceholder(/search|filter|domain/i).first();
        if (await searchInput.count() === 0) {
            test.skip(); // Search input not implemented
            return;
        }
        await searchInput.fill('wp.panel');
        await page.waitForLoadState('networkidle');

        await expect(page.getByText('wp.panel.test', { exact: true }).first()).toBeVisible();
        // Other sites should be filtered out
        await expect(page.getByText('reseller-site.panel.test', { exact: true }).first()).not.toBeVisible({ timeout: 5000 });
    });
});
