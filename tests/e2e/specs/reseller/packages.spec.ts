import { test, expect } from '@playwright/test';

test.describe('Reseller Packages', () => {
    test('packages page loads', async ({ page }) => {
        await page.goto('/reseller/packages');
        await page.waitForLoadState('networkidle');

        await expect(page).not.toHaveURL(/login/);
        await expect(page.getByText(/package/i).first()).toBeVisible({ timeout: 15_000 });
    });

    test('shows reseller-owned packages', async ({ page }) => {
        await page.goto('/reseller/packages');
        await page.waitForLoadState('networkidle');

        // seed/002_packages.sql: id=4 "Reseller Starter", id=5 "Reseller Growth" (reseller_id=2)
        await expect(page.getByText('Reseller Starter')).toBeVisible({ timeout: 15_000 });
        await expect(page.getByText('Reseller Growth')).toBeVisible({ timeout: 5_000 });
    });

    test('create package button opens form', async ({ page }) => {
        await page.goto('/reseller/packages');
        await page.waitForLoadState('networkidle');

        const createBtn = page
            .getByRole('button', { name: /create|new package|add package/i })
            .first();
        await expect(createBtn).toBeVisible({ timeout: 15_000 });
        await createBtn.click();

        const nameInput = page.getByPlaceholder(/starter|business|enterprise/i);
        await expect(nameInput.first()).toBeVisible({ timeout: 10_000 });
    });

    test('package shows disk and bandwidth limits', async ({ page }) => {
        await page.goto('/reseller/packages');
        await page.waitForLoadState('networkidle');

        const limit = page.getByText(/disk|bandwidth|quota|MB|GB/i).first();
        await expect(limit).toBeVisible({ timeout: 15_000 });
    });

    test('edit and delete buttons are present', async ({ page }) => {
        await page.goto('/reseller/packages');
        await page.waitForLoadState('networkidle');

        await expect(page.getByRole('button', { name: /deactivate/i }).first()).toBeVisible({
            timeout: 15_000,
        });
        await expect(page.getByRole('button', { name: /delete|remove/i }).first()).toBeVisible({
            timeout: 5_000,
        });
    });
});
