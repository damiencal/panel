import { test, expect } from '@playwright/test';
import { AdminMonitoringPage } from '../../pages/admin/MonitoringPage';

test.describe('Admin Monitoring', () => {
    test('monitoring page loads without error', async ({ page }) => {
        const mon = new AdminMonitoringPage(page);
        await mon.goto();

        await expect(page).not.toHaveURL(/login/);
        const error = page.getByText(/internal server error|500|unhandled/i);
        await expect(error).not.toBeVisible({ timeout: 5000 });
    });

    test('shows CPU or memory metrics', async ({ page }) => {
        const mon = new AdminMonitoringPage(page);
        await mon.goto();

        const metric = page.getByText(/cpu|memory|ram|load/i).first();
        await expect(metric).toBeVisible({ timeout: 15_000 });
    });

    test('shows process list with PID column', async ({ page }) => {
        const mon = new AdminMonitoringPage(page);
        await mon.goto();

        // Click the Processes tab to load the process table
        await page.getByRole('button', { name: /processes/i }).click();
        await page.waitForTimeout(1000);

        const header = page
            .getByRole('columnheader', { name: /pid|process|command/i })
            .first();
        await expect(header).toBeVisible({ timeout: 15_000 });
    });

    test('process list has rows', async ({ page }) => {
        const mon = new AdminMonitoringPage(page);
        await mon.goto();

        // Click the Processes tab first
        await page.getByRole('button', { name: /processes/i }).click();
        await page.waitForTimeout(1000);

        // Process table should show running processes
        const processRow = page.locator('tbody tr').first();
        await expect(processRow).toBeVisible({ timeout: 15_000 });
    });

    test('kill process button is present', async ({ page }) => {
        const mon = new AdminMonitoringPage(page);
        await mon.goto();

        // Click the Processes tab first
        await page.getByRole('button', { name: /processes/i }).click();
        await page.waitForTimeout(1000);

        const killBtn = page.getByRole('button', { name: /kill|terminate|end/i }).first();
        await expect(killBtn).toBeVisible({ timeout: 15_000 });
    });
});
