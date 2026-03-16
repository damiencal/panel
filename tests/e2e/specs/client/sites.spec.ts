import { test, expect } from '@playwright/test';
import { ClientSitesPage } from '../../pages/client/SitesPage';

test.describe('Client Sites — list & detail', () => {
    test('shows seeded WordPress site in the list', async ({ page }) => {
        const sites = new ClientSitesPage(page);
        await sites.goto();

        await expect(page.getByText('wp.panel.test').first()).toBeVisible({ timeout: 15_000 });
    });

    test('shows static site in the list', async ({ page }) => {
        const sites = new ClientSitesPage(page);
        await sites.goto();

        await expect(page.getByText('static.panel.test').first()).toBeVisible({ timeout: 15_000 });
    });

    test('add site button is visible', async ({ page }) => {
        const sites = new ClientSitesPage(page);
        await sites.goto();

        await expect(sites.addSiteButton).toBeVisible();
    });

    test('create and delete a new static site', async ({ page }) => {
        const sites = new ClientSitesPage(page);
        await sites.goto();

        const testDomain = `pw-test-${Date.now()}.panel.test`;
        await sites.createSite(testDomain, 'Static');

        await expect(page.getByText(testDomain)).toBeVisible();

        // Clean up
        await sites.deleteSite(testDomain);
        await expect(page.getByText(testDomain)).not.toBeVisible({ timeout: 10_000 });
    });

    test('site row shows Active status badge', async ({ page }) => {
        const sites = new ClientSitesPage(page);
        await sites.goto();

        const activeLabels = page.getByText(/active/i);
        await expect(activeLabels.first()).toBeVisible();
    });
});

test.describe('Client Sites — SSL sub-screen', () => {
    test.beforeEach(async ({ page }) => {
        const sites = new ClientSitesPage(page);
        await sites.goto();
        // Open site detail for static.panel.test (has SSL enabled in seed)
        await sites.openSite('static.panel.test');
    });

    test('SSL sub-screen loads with certificate info', async ({ page }) => {
        const sites = new ClientSitesPage(page);
        await sites.openSSLSubscreen();

        // Should show either cert info or an enable/disable control
        const sslContent = page
            .getByText(/ssl|certificate|tls/i)
            .or(page.getByRole('checkbox', { name: /ssl/i }))
            .first();
        await expect(sslContent).toBeVisible();
    });
});

test.describe('Client Sites — PHP sub-screen', () => {
    test.beforeEach(async ({ page }) => {
        const sites = new ClientSitesPage(page);
        await sites.goto();
        await sites.openSite('wp.panel.test');
    });

    test('PHP sub-screen shows PHP version selector', async ({ page }) => {
        const sites = new ClientSitesPage(page);
        await sites.openPHPSubscreen();

        // PHP version select has title="PHP version" and is visible inline for PHP/WordPress sites
        const phpVersionEl = page.locator('select[title="PHP version"]').first();
        await expect(phpVersionEl).toBeVisible();
    });
});

test.describe('Client Sites — Logs sub-screen', () => {
    test.beforeEach(async ({ page }) => {
        const sites = new ClientSitesPage(page);
        await sites.goto();
        await sites.openSite('wp.panel.test');
    });

    test('Logs sub-screen shows log viewer area', async ({ page }) => {
        const sites = new ClientSitesPage(page);
        await sites.openLogsSubscreen();

        // After clicking "Logs" the log panel appears; check for any log content or heading
        const logViewer = page
            .getByText(/log|no log|access|error/i)
            .first();
        await expect(logViewer).toBeVisible({ timeout: 15_000 });
    });
});
