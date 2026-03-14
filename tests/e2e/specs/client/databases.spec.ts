import { test, expect } from '@playwright/test';
import { ClientDatabasesPage } from '../../pages/client/DatabasesPage';

test.describe('Client Databases', () => {
    test('shows seeded databases in the list', async ({ page }) => {
        const dbs = new ClientDatabasesPage(page);
        await dbs.goto();

        await expect(page.getByText('client_wp')).toBeVisible();
        await expect(page.getByText('client_dev')).toBeVisible();
    });

    test('shows database user for each database', async ({ page }) => {
        const dbs = new ClientDatabasesPage(page);
        await dbs.goto();

        // Database users are shown after expanding the Manage Users section
        await page.getByRole('button', { name: /manage users/i }).first().click();
        await page.waitForTimeout(500);
        await expect(page.getByText(/client_wp_user|client_dev_user/i).first()).toBeVisible();
    });

    test('create and delete a database', async ({ page }) => {
        const dbs = new ClientDatabasesPage(page);
        await dbs.goto();

        const dbName = `test_${Date.now()}`;
        await dbs.createDatabase(dbName);

        await expect(page.getByText(dbName)).toBeVisible({ timeout: 15_000 });

        await dbs.deleteDatabase(dbName);
        await expect(page.getByText(dbName)).not.toBeVisible({ timeout: 10_000 });
    });

    test('shows Active status for seeded databases', async ({ page }) => {
        const dbs = new ClientDatabasesPage(page);
        await dbs.goto();

        await expect(page.getByText(/active/i).first()).toBeVisible();
    });

    test('database list shows MariaDB type badge', async ({ page }) => {
        const dbs = new ClientDatabasesPage(page);
        await dbs.goto();

        await expect(page.getByText(/mariadb/i).first()).toBeVisible();
    });
});
