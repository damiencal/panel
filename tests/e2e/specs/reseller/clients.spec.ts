import { test, expect } from '@playwright/test';

test.describe('Reseller Clients', () => {
    test('clients page loads', async ({ page }) => {
        await page.goto('/reseller/clients');
        await page.waitForLoadState('networkidle');

        await expect(page).not.toHaveURL(/login/);
        await expect(page.getByText(/client/i).first()).toBeVisible({ timeout: 15_000 });
    });

    test('shows seeded client (user id 3)', async ({ page }) => {
        await page.goto('/reseller/clients');
        await page.waitForLoadState('networkidle');

        await expect(page.getByText('client@panel.test').first()).toBeVisible({ timeout: 15_000 });
    });

    test('create client button opens form', async ({ page }) => {
        await page.goto('/reseller/clients');
        await page.waitForLoadState('networkidle');

        const createBtn = page
            .getByRole('button', { name: /create|add client|new client/i })
            .first();
        await expect(createBtn).toBeVisible({ timeout: 15_000 });
        await createBtn.click();

        const emailInput = page.getByPlaceholder(/john@example/i);
        await expect(emailInput.first()).toBeVisible({ timeout: 10_000 });
    });

    test('client row shows package assignment', async ({ page }) => {
        await page.goto('/reseller/clients');
        await page.waitForLoadState('networkidle');

        // client uses package id=4 "Reseller Starter" from seed
        const pkg = page.getByText(/Reseller Starter|starter|package/i).first();
        await expect(pkg).toBeVisible({ timeout: 15_000 });
    });

    test('suspend client button is present', async ({ page }) => {
        await page.goto('/reseller/clients');
        await page.waitForLoadState('networkidle');

        const btn = page.getByRole('button', { name: /suspend|disable/i }).first();
        await expect(btn).toBeVisible({ timeout: 15_000 });
    });
});
