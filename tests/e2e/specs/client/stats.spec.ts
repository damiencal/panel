import { test, expect } from '@playwright/test';

test.describe('Client Web Stats', () => {
    test('stats page loads without error', async ({ page }) => {
        await page.goto('/stats');
        await page.waitForLoadState('networkidle');

        // Should not show a critical error
        const errorMsg = page.getByText(/internal server error|500|unhandled/i);
        await expect(errorMsg).not.toBeVisible({ timeout: 5000 });
    });

    test('stats page has a site selector or stats content', async ({ page }) => {
        await page.goto('/stats');
        await page.waitForLoadState('networkidle');

        // The stats page shows a "Web Statistics" heading and tool cards (Webalizer, GoAccess, AWStats)
        const content = page.getByText(/web statistics|webalizer|goaccess|awstats/i).first();
        await expect(content).toBeVisible({ timeout: 10_000 });
    });
});
