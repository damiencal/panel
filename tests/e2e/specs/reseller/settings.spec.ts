import { test, expect } from '@playwright/test';

test.describe('Reseller Settings', () => {
    test('settings page loads', async ({ page }) => {
        await page.goto('/reseller/settings');
        await page.waitForLoadState('networkidle');

        await expect(page).not.toHaveURL(/login/);
        await expect(page.getByText(/settings/i).first()).toBeVisible({ timeout: 15_000 });
    });

    test('two-factor authentication section is present', async ({ page }) => {
        await page.goto('/reseller/settings');
        await page.waitForLoadState('networkidle');

        // Settings page shows Security section with Two-Factor Authentication
        const twoFaSection = page.getByRole('heading', { name: /two.factor/i });
        await expect(twoFaSection.first()).toBeVisible({ timeout: 15_000 });
    });

    test('change password form is accessible', async ({ page }) => {
        await page.goto('/reseller/settings');
        await page.waitForLoadState('networkidle');

        // Change password form is visible directly on the settings page
        const pwdInput = page.getByRole('button', { name: /change password/i });
        await expect(pwdInput.first()).toBeVisible({ timeout: 15_000 });
    });

    test('profile email field shows seeded email', async ({ page }) => {
        await page.goto('/reseller/settings');
        await page.waitForLoadState('networkidle');

        // use .first() to avoid matching both nav header and account info
        await expect(page.getByText('reseller@panel.test').first()).toBeVisible({ timeout: 15_000 });
    });

    test('security action button is present', async ({ page }) => {
        await page.goto('/reseller/settings');
        await page.waitForLoadState('networkidle');

        // Settings page has "Change Password" and "Enable Two-Factor Auth" buttons
        const btn = page.getByRole('button', { name: /change password|enable two.factor/i }).first();
        await expect(btn).toBeVisible({ timeout: 15_000 });
    });
});
