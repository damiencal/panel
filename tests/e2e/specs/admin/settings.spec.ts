import { test, expect } from '@playwright/test';

test.describe('Admin Settings', () => {
    test('settings page loads', async ({ page }) => {
        await page.goto('/admin/settings');
        await page.waitForLoadState('networkidle');

        await expect(page).not.toHaveURL(/login/);
        await expect(page.getByText(/settings/i).first()).toBeVisible({ timeout: 15_000 });
    });

    test('panel configuration section is visible', async ({ page }) => {
        await page.goto('/admin/settings');
        await page.waitForLoadState('networkidle');

        // Admin settings shows panel configuration info (settings via panel.toml)
        await expect(page.getByRole('heading', { name: /panel configuration/i })).toBeVisible({ timeout: 15_000 });
    });

    test('panel.toml configuration note is shown', async ({ page }) => {
        await page.goto('/admin/settings');
        await page.waitForLoadState('networkidle');

        // Settings page explains configuration is via panel.toml
        const note = page.getByText(/panel\.toml|environment variable/i).first();
        await expect(note).toBeVisible({ timeout: 15_000 });
    });

    test('key settings info is displayed', async ({ page }) => {
        await page.goto('/admin/settings');
        await page.waitForLoadState('networkidle');

        // Settings page shows key configuration variables
        const keyInfo = page.getByText(/PANEL_SECRET_KEY|DATABASE_URL|server port/i).first();
        await expect(keyInfo).toBeVisible({ timeout: 15_000 });
    });

    test('settings heading is visible', async ({ page }) => {
        await page.goto('/admin/settings');
        await page.waitForLoadState('networkidle');

        await expect(page.getByRole('heading', { name: 'Settings' })).toBeVisible({ timeout: 15_000 });
    });
});
