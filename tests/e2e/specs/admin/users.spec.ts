import { test, expect } from '@playwright/test';
import { AdminUsersPage } from '../../pages/admin/UsersPage';

test.describe('Admin Users — Clients', () => {
    test('shows seeded client user in the list', async ({ page }) => {
        const users = new AdminUsersPage(page);
        await users.gotoClients();

        // Use row/cell selectors to avoid matching the nav header username
        await expect(page.getByRole('cell', { name: 'client', exact: true }).first()).toBeVisible();
        await expect(page.getByText('client@panel.test').first()).toBeVisible();
    });

    test('client shows package assignment', async ({ page }) => {
        const users = new AdminUsersPage(page);
        await users.gotoClients();

        // Open the Add Client form to verify package options exist in the dropdown
        await page.getByRole('button', { name: /add client/i }).first().click();
        const pkgOption = page.locator('option').filter({ hasText: /basic|pro|business|starter|growth/i });
        await expect(pkgOption.first()).toBeAttached({ timeout: 10_000 });
    });

    test('impersonate client — session switches to client dashboard', async ({ page }) => {
        const users = new AdminUsersPage(page);
        await users.gotoClients();

        await users.impersonateUser('client');

        // Should land on a client-portal page (/ or /dashboard) with impersonation banner
        const impersonationBanner = page
            .getByText(/impersonat|logged in as|viewing as/i)
            .first();
        await expect(impersonationBanner).toBeVisible({ timeout: 15_000 });
    });
});

test.describe('Admin Users — Resellers', () => {
    test('shows seeded reseller in the list', async ({ page }) => {
        const users = new AdminUsersPage(page);
        await users.gotoResellers();

        // Username is in a <span> inside an avatar div; cell text includes the avatar letter
        await expect(page.getByText('reseller', { exact: true }).first()).toBeVisible();
        await expect(page.getByText('reseller@panel.test').first()).toBeVisible();
    });

    test('impersonate reseller', async ({ page }) => {
        const users = new AdminUsersPage(page);
        await users.gotoResellers();

        await users.impersonateUser('reseller');

        const banner = page.getByText(/impersonat|logged in as|viewing as/i).first();
        await expect(banner).toBeVisible({ timeout: 15_000 });
    });
});
