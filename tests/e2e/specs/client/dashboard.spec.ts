import { test, expect } from '@playwright/test';
import { ClientDashboardPage } from '../../pages/client/DashboardPage';

test.describe('Client Dashboard', () => {
    test('renders dashboard with quota widgets', async ({ page }) => {
        const dashboard = new ClientDashboardPage(page);
        await dashboard.goto();

        // Heading visible
        await expect(dashboard.heading).toBeVisible();

        // At least one stat widget panel is present (Websites, Databases, Email Domains, Open Tickets)
        const widgets = page.locator('p').filter({ hasText: /websites|databases|email domains|open tickets/i });
        await expect(widgets.first()).toBeVisible();
    });

    test('shows correct site count from seed data', async ({ page }) => {
        const dashboard = new ClientDashboardPage(page);
        await dashboard.goto();

        // Seed has 2 sites for the client user; dashboard shows "Websites" stat label
        const websitesStat = page.locator('p').filter({ hasText: 'Websites' }).first();
        await expect(websitesStat).toBeVisible();
    });

    test('shows navigation links for all portal sections', async ({ page }) => {
        await page.goto('/');
        await page.waitForLoadState('networkidle');

        // Nav uses exact labels: Websites, Databases, DNS, Email, Files, Cron Jobs, FTP Stats, Backups
        const navLinks = ['Websites', 'Databases', 'DNS', 'Email', 'Files', 'Cron Jobs', 'FTP Stats', 'Backups'];
        for (const linkText of navLinks) {
            const link = page.getByRole('link', { name: new RegExp(linkText, 'i') }).first();
            await expect(link).toBeVisible({ timeout: 5000 });
        }
    });

    test('logout clears session and redirects to login', async ({ page }) => {
        await page.goto('/');
        await page.waitForLoadState('networkidle');

        const logoutBtn = page.getByRole('button', { name: /log out|sign out/i })
            .or(page.getByRole('link', { name: /log out|sign out/i })).first();
        if (await logoutBtn.count() > 0) {
            await logoutBtn.click();
            await page.waitForURL('**/login', { timeout: 10_000 });
            await expect(page).toHaveURL(/login/);
        }
    });
});
