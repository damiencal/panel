import { test, expect } from '@playwright/test';

test.describe('Client Backups', () => {
    test('shows backup schedule list', async ({ page }) => {
        await page.goto('/backups');
        await page.waitForLoadState('networkidle');

        await expect(page.getByText(/WP Daily Backup|daily/i).first()).toBeVisible();
    });

    test('shows backup run history with completed runs', async ({ page }) => {
        await page.goto('/backups');
        await page.waitForLoadState('networkidle');

        await expect(page.getByText(/success/i)).toBeVisible();
    });

    test('shows a failed backup run entry', async ({ page }) => {
        await page.goto('/backups');
        await page.waitForLoadState('networkidle');

        await expect(page.getByText(/failed/i)).toBeVisible();
    });

    test('trigger manual backup button is accessible', async ({ page }) => {
        await page.goto('/backups');
        await page.waitForLoadState('networkidle');

        const backupBtn = page.getByRole('button', { name: /run now|backup now|trigger/i }).first();
        await expect(backupBtn).toBeVisible();
    });

    test('shows archive size for successful run', async ({ page }) => {
        await page.goto('/backups');
        await page.waitForLoadState('networkidle');

        // Seed backup run has 52428800 bytes; panel displays formatted size (e.g., "98.8 MB" cumulative)
        const sizeEl = page.getByText(/\d+\.?\d*\s*MB/i).first();
        await expect(sizeEl).toBeVisible();
    });
});
