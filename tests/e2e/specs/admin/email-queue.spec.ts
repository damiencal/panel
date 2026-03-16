import { test, expect } from '@playwright/test';

test.describe('Admin Mail Queue', () => {
    test('mail queue page loads', async ({ page }) => {
        await page.goto('/admin/mail-queue');
        await page.waitForLoadState('networkidle');

        await expect(page).not.toHaveURL(/login/);
        await expect(
            page.getByText(/mail queue|mail-queue|queue/i).first()
        ).toBeVisible({ timeout: 15_000 });
    });

    test('shows queue list or empty state', async ({ page }) => {
        await page.goto('/admin/mail-queue');
        await page.waitForLoadState('networkidle');

        // Either a table with emails or an empty state message
        const content = page
            .getByRole('table')
            .or(page.getByRole('list'))
            .or(page.getByText(/empty|no mail|no messages|queue is empty/i));
        await expect(content.first()).toBeVisible({ timeout: 15_000 });
    });

    test('flush or retry button is visible', async ({ page }) => {
        await page.goto('/admin/mail-queue');
        await page.waitForLoadState('networkidle');

        const btn = page
            .getByRole('button', { name: /flush|retry|resend|refresh/i })
            .first();
        await expect(btn).toBeVisible({ timeout: 15_000 });
    });

    test('refresh queue button reloads without error', async ({ page }) => {
        await page.goto('/admin/mail-queue');
        await page.waitForLoadState('networkidle');

        const refresh = page.getByRole('button', { name: /refresh|reload/i }).first();
        if (await refresh.isVisible()) {
            await refresh.click();
            await page.waitForLoadState('networkidle');
            await expect(page).not.toHaveURL(/error|500/);
        }
    });
});
