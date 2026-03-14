import { test, expect } from '@playwright/test';

test.describe('Client Cron Jobs', () => {
    // Helper: navigate to cron page and select wp.panel.test to load cron jobs
    async function gotoCronWithSite(page: import('@playwright/test').Page) {
        await page.goto('/cron');
        await page.waitForLoadState('networkidle');
        await page.locator('select').selectOption({ label: 'wp.panel.test' });
        await page.waitForTimeout(500);
    }

    test('shows seeded cron jobs', async ({ page }) => {
        await gotoCronWithSite(page);
        await expect(page.getByText(/wp-cron|WordPress Cron/i).first()).toBeVisible();
    });

    test('shows cron schedule', async ({ page }) => {
        await gotoCronWithSite(page);
        await expect(page.getByText(/\*\/5 \* \* \* \*/)).toBeVisible();
    });

    test('add a cron job', async ({ page }) => {
        await gotoCronWithSite(page);

        // Add form is always visible when a site is selected (no toggle button needed)
        await page.getByPlaceholder(/\*\/5 \* \* \* \*/i).fill('0 2 * * *');
        await page.getByPlaceholder(/\/usr\/bin\/php/i).fill('/usr/bin/test-command');
        const descField = page.getByPlaceholder(/description|label/i);
        if (await descField.count() > 0) await descField.fill('E2E test cron');

        await page.getByRole('button', { name: /add cron job/i }).click();
        await page.waitForLoadState('networkidle');

        await expect(page.getByText(/test-command/i).first()).toBeVisible({ timeout: 10_000 });
    });

    test('delete a cron job', async ({ page }) => {
        await gotoCronWithSite(page);

        // Delete the "E2E test cron" job created above (if it exists)
        const testRow = page.locator('tr:has-text("test-command"), [class*="row"]:has-text("test-command")').first();
        if (await testRow.count() > 0) {
            await testRow.getByRole('button', { name: /delete|remove/i }).click();
            await page.getByRole('button', { name: /confirm|yes/i }).last().click();
            await page.waitForLoadState('networkidle');
            await expect(page.getByText(/test-command/i)).not.toBeVisible({ timeout: 10_000 });
        }
    });

    test('enable/disable toggle exists on cron job row', async ({ page }) => {
        await gotoCronWithSite(page);

        // Toggle is a custom button with title="Disable job" or "Enable job"
        const toggle = page.getByRole('button', { name: /disable job|enable job/i }).first();
        await expect(toggle).toBeVisible();
    });
});
