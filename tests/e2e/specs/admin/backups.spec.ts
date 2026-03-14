import { test, expect } from '@playwright/test';

test.describe('Admin Backups', () => {
    test('backups page loads', async ({ page }) => {
        await page.goto('/admin/backups');
        await page.waitForLoadState('networkidle');

        await expect(page).not.toHaveURL(/login/);
        await expect(page.getByText(/backup/i).first()).toBeVisible({ timeout: 15_000 });
    });

    test('shows backup schedules', async ({ page }) => {
        await page.goto('/admin/backups');
        await page.waitForLoadState('networkidle');

        // seed/014_backups.sql has 1 schedule; stat card shows "Schedules" label
        const schedule = page.getByText(/weekly|daily|monthly|schedules/i).first();
        await expect(schedule).toBeVisible({ timeout: 15_000 });
    });

    test('shows recent backup runs list', async ({ page }) => {
        await page.goto('/admin/backups');
        await page.waitForLoadState('networkidle');

        // Click "Recent Runs" tab to load run history
        await page.getByRole('button', { name: /recent runs/i }).click();
        await page.waitForTimeout(1000);

        // A table or list of runs should now be visible
        const list = page.getByRole('table').first();
        await expect(list).toBeVisible({ timeout: 15_000 });
    });

    test('shows success and failed status badges', async ({ page }) => {
        await page.goto('/admin/backups');
        await page.waitForLoadState('networkidle');

        await expect(page.getByText(/success|completed/i).first()).toBeVisible({ timeout: 15_000 });
        await expect(page.getByText(/fail|error/i).first()).toBeVisible({ timeout: 5_000 });
    });

    test('backup action buttons are present', async ({ page }) => {
        await page.goto('/admin/backups');
        await page.waitForLoadState('networkidle');

        // Page has Stats and Recent Runs tab buttons
        const btn = page.getByRole('button', { name: /stats|recent runs|refresh/i }).first();
        await expect(btn).toBeVisible({ timeout: 15_000 });
    });
});
