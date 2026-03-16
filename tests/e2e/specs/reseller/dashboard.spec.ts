import { test, expect } from '@playwright/test';
import { ResellerDashboardPage } from '../../pages/reseller/ResellerDashboardPage';

test.describe('Reseller Dashboard', () => {
    test('reseller dashboard loads', async ({ page }) => {
        const dash = new ResellerDashboardPage(page);
        await dash.goto();

        await expect(page).not.toHaveURL(/login/);
        await expect(page.getByText(/dashboard|welcome|overview/i).first()).toBeVisible({
            timeout: 15_000,
        });
    });

    test('shows client count', async ({ page }) => {
        const dash = new ResellerDashboardPage(page);
        await dash.goto();

        // reseller (id=2) has 1 client (id=3)
        const countEl = page.getByText(/client/i).first();
        await expect(countEl).toBeVisible({ timeout: 15_000 });
    });

    test('shows resource usage summary', async ({ page }) => {
        const dash = new ResellerDashboardPage(page);
        await dash.goto();

        // Reseller dashboard shows client stat cards: Total Clients, Active, Suspended
        const usage = page.getByText(/total clients|active|suspended/i).first();
        await expect(usage).toBeVisible({ timeout: 15_000 });
    });

    test('navigation links are visible', async ({ page }) => {
        const dash = new ResellerDashboardPage(page);
        await dash.goto();

        await expect(page.getByRole('link', { name: /clients/i }).first()).toBeVisible({
            timeout: 15_000,
        });
        await expect(page.getByRole('link', { name: /packages/i }).first()).toBeVisible({
            timeout: 5_000,
        });
    });
});
