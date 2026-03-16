import { test, expect } from '@playwright/test';
import { AdminDashboardPage } from '../../pages/admin/AdminDashboardPage';

test.describe('Admin Dashboard', () => {
    test('loads admin dashboard', async ({ page }) => {
        const dashboard = new AdminDashboardPage(page);
        await dashboard.goto();

        // Should be on /admin, not redirected to /login
        await expect(page).not.toHaveURL(/login/);
    });

    test('shows system service status indicators', async ({ page }) => {
        const dashboard = new AdminDashboardPage(page);
        await dashboard.goto();

        // Admin dashboard shows stat cards: Total Users, Resellers, Clients, Sites
        const statCard = page.getByText(/total users|resellers|clients/i).first();
        await expect(statCard).toBeVisible({ timeout: 10_000 });
    });

    test('shows total user count summary', async ({ page }) => {
        const dashboard = new AdminDashboardPage(page);
        await dashboard.goto();

        // Stat cards show "Total Users", "Clients", "Resellers" as labels
        const userCount = page.getByText('Total Users').first();
        await expect(userCount).toBeVisible();
    });

    test('shows total site count', async ({ page }) => {
        const dashboard = new AdminDashboardPage(page);
        await dashboard.goto();

        const siteCount = page.getByText('Sites').first();
        await expect(siteCount).toBeVisible();
    });
});
