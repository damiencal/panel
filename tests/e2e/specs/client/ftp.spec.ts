import { test, expect } from '@playwright/test';

test.describe('Client FTP Accounts', () => {
    test('shows seeded FTP account', async ({ page }) => {
        await page.goto('/ftp');
        await page.waitForLoadState('networkidle');

        // /ftp shows FTP Usage Statistics; client_ftp appears in Per-Account Breakdown table
        await expect(page.getByText('client_ftp')).toBeVisible();
    });

    test('shows Active status in FTP stats', async ({ page }) => {
        await page.goto('/ftp');
        await page.waitForLoadState('networkidle');

        // Stat card shows "Active" label for active accounts count
        await expect(page.getByText(/active/i).first()).toBeVisible();
    });

    test('shows FTP usage statistics heading', async ({ page }) => {
        await page.goto('/ftp');
        await page.waitForLoadState('networkidle');

        await expect(page.getByRole('heading', { name: /FTP Usage Statistics/i })).toBeVisible();
    });

    test('per-account breakdown table is visible', async ({ page }) => {
        await page.goto('/ftp');
        await page.waitForLoadState('networkidle');

        // Table has columns: Username, Uploads, Downloads, etc.
        await expect(page.getByRole('columnheader', { name: /username/i })).toBeVisible();
    });
});
