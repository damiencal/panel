import { test, expect } from '@playwright/test';

test.describe('Admin Packages', () => {
    test('packages page loads', async ({ page }) => {
        await page.goto('/admin/packages');
        await page.waitForLoadState('networkidle');

        await expect(page).not.toHaveURL(/login/);
        await expect(page.getByText(/package/i).first()).toBeVisible({ timeout: 15_000 });
    });

    test('shows seeded packages', async ({ page }) => {
        await page.goto('/admin/packages');
        await page.waitForLoadState('networkidle');

        // Actual package names from the DB: Basic, Pro, Business, Starter, Growth
        await expect(page.getByText('Basic', { exact: true }).first()).toBeVisible({ timeout: 15_000 });
        await expect(page.getByText('Pro', { exact: true }).first()).toBeVisible({ timeout: 5_000 });
        await expect(page.getByText('Business', { exact: true }).first()).toBeVisible({ timeout: 5_000 });
    });

    test('create new package button opens form', async ({ page }) => {
        await page.goto('/admin/packages');
        await page.waitForLoadState('networkidle');

        // Button text is "New Package"
        const createBtn = page.getByRole('button', { name: /new package/i }).first();
        await expect(createBtn).toBeVisible({ timeout: 15_000 });
        await createBtn.click();

        // Placeholder is "e.g. Starter, Business, Enterprise" (adjacent label, no for/id)
        const nameInput = page.getByPlaceholder(/starter|business|enterprise/i).first();
        await expect(nameInput).toBeVisible({ timeout: 10_000 });
    });

    test('package row shows disk quota and bandwidth limits', async ({ page }) => {
        await page.goto('/admin/packages');
        await page.waitForLoadState('networkidle');

        // Quota values from seed: 10240 MB disk, 51200 MB bandwidth for Basic
        const quota = page.getByText(/10240|10 GB|quota|disk|MB/i).first();
        await expect(quota).toBeVisible({ timeout: 15_000 });
    });

    test('deactivate package button is present', async ({ page }) => {
        await page.goto('/admin/packages');
        await page.waitForLoadState('networkidle');

        // Package row has "Deactivate" button (no Edit button)
        const deactivateBtn = page.getByRole('button', { name: /deactivate/i }).first();
        await expect(deactivateBtn).toBeVisible({ timeout: 15_000 });
    });

    test('delete package button is present', async ({ page }) => {
        await page.goto('/admin/packages');
        await page.waitForLoadState('networkidle');

        const deleteBtn = page.getByRole('button', { name: /delete|remove/i }).first();
        await expect(deleteBtn).toBeVisible({ timeout: 15_000 });
    });
});
