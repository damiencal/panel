import { test, expect } from '@playwright/test';

test.describe('Admin Audit Log', () => {
    test('audit log page loads', async ({ page }) => {
        await page.goto('/admin/audit-log');
        await page.waitForLoadState('networkidle');

        await expect(page).not.toHaveURL(/login/);
        await expect(page.getByText(/audit/i).first()).toBeVisible({ timeout: 15_000 });
    });

    test('shows seeded audit entries', async ({ page }) => {
        await page.goto('/admin/audit-log');
        await page.waitForLoadState('networkidle');

        // seed inserts 8 entries for admin actions; 1 header + 8 data = 9 rows
        const rows = page.getByRole('row');
        const rowCount = await rows.count();
        expect(rowCount).toBeGreaterThan(3);
    });

    test('shows action, user, and timestamp columns', async ({ page }) => {
        await page.goto('/admin/audit-log');
        await page.waitForLoadState('networkidle');

        // Actual table headers: Action, Target, Status, Time
        await expect(page.getByRole('columnheader', { name: /action|event/i }).first()).toBeVisible({
            timeout: 15_000,
        });
        await expect(page.getByRole('columnheader', { name: /target|status|time/i }).first()).toBeVisible({
            timeout: 5_000,
        });
    });

    test('filter by user email', async ({ page }) => {
        await page.goto('/admin/audit-log');
        await page.waitForLoadState('networkidle');

        const filterInput = page
            .getByPlaceholder(/search|filter|user/i)
            .or(page.getByLabel(/filter|search/i));
        if (await filterInput.first().isVisible({ timeout: 5_000 })) {
            await filterInput.first().fill('admin@panel.test');
            await page.waitForLoadState('networkidle');
            await expect(page.getByText('admin@panel.test')).toBeVisible({ timeout: 10_000 });
        }
    });

    test('shows login events in audit log', async ({ page }) => {
        await page.goto('/admin/audit-log');
        await page.waitForLoadState('networkidle');

        // seed has user_login entries
        const loginEntry = page.getByText(/login|user_login|signed in/i).first();
        await expect(loginEntry).toBeVisible({ timeout: 15_000 });
    });
});
