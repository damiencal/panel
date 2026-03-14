import { test, expect } from '@playwright/test';
import { ClientDNSPage } from '../../pages/client/DNSPage';

test.describe('Client DNS — zones', () => {
    test('shows seeded DNS zones in the list', async ({ page }) => {
        const dns = new ClientDNSPage(page);
        await dns.goto();

        // Use exact matching to avoid matching subdomains or email addresses
        await expect(page.getByText('panel.test', { exact: true })).toBeVisible();
        await expect(page.getByText('wp.panel.test', { exact: true })).toBeVisible();
    });

    test('zone shows Synced status', async ({ page }) => {
        const dns = new ClientDNSPage(page);
        await dns.goto();

        await expect(page.getByText(/synced/i).first()).toBeVisible();
    });
});

test.describe('Client DNS — records', () => {
    test.beforeEach(async ({ page }) => {
        const dns = new ClientDNSPage(page);
        await dns.goto();
        await dns.selectZone('panel.test');
    });

    test('shows seeded A records for panel.test', async ({ page }) => {
        await expect(page.getByText('127.0.0.1').first()).toBeVisible();
    });

    test('shows MX record', async ({ page }) => {
        await expect(page.getByText(/MX/i).first()).toBeVisible();
    });

    test('shows TXT SPF record', async ({ page }) => {
        await expect(page.getByText(/spf/i)).toBeVisible();
    });

    test('add and delete a TXT record', async ({ page }) => {
        const dns = new ClientDNSPage(page);
        const uniqueName = `_verify-${Date.now()}`;

        await dns.addRecord('TXT', uniqueName, '"v=testrecord"');
        await expect(page.getByText(uniqueName)).toBeVisible({ timeout: 15_000 });

        await dns.deleteRecord(uniqueName);
        await expect(page.getByText(uniqueName)).not.toBeVisible({ timeout: 10_000 });
    });
});
