/**
 * pages/client/SitesPage.ts
 */
import { Page, Locator } from '@playwright/test';

export class ClientSitesPage {
    readonly addSiteButton: Locator;
    readonly siteList: Locator;
    private currentDomain: string | null = null;

    constructor(private readonly page: Page) {
        this.addSiteButton = page.getByRole('button', { name: 'Add Site' });
        this.siteList = page.locator('table tbody tr, [class*="site-row"], [class*="card"]');
    }

    async goto() {
        await this.page.goto('/sites');
        await this.page.waitForLoadState('networkidle');
    }

    async openSite(domain: string) {
        // Sites are displayed as inline table rows — no separate detail page.
        // Track the domain so sub-screen methods can scope to the right row.
        this.currentDomain = domain;
        const row = this.page.locator('tr').filter({ hasText: domain }).first();
        await row.scrollIntoViewIfNeeded();
        await this.page.waitForTimeout(300);
    }

    async openSiteMenu(domain: string) {
        const row = this.page.locator(`tr:has-text("${domain}"), [class*="card"]:has-text("${domain}")`).first();
        await row.getByRole('button', { name: /manage|settings|actions/i }).first().click();
    }

    /** Click the "Cert" toggle button for the current site to open SSL cert info inline. */
    async openSSLSubscreen() {
        const row = this.currentDomain
            ? this.page.locator('tr').filter({ hasText: this.currentDomain }).first()
            : this.page.locator('tr').nth(1);
        await row.getByRole('button', { name: /cert/i }).click();
        await this.page.waitForTimeout(500);
    }

    /** PHP version selector is always visible inline for PHP sites — no extra click needed. */
    async openPHPSubscreen() {
        await this.page.waitForTimeout(300);
    }

    /** Click the "Logs" toggle button to open the log viewer inline. */
    async openLogsSubscreen() {
        const row = this.currentDomain
            ? this.page.locator('tr').filter({ hasText: this.currentDomain }).first()
            : this.page.locator('tr').nth(1);
        await row.getByRole('button', { name: 'Logs' }).click();
        await this.page.waitForTimeout(500);
    }

    async createSite(domain: string, siteType = 'Static') {
        // Fill domain input (placeholder "example.com") and select site type, then submit
        await this.page.getByPlaceholder('example.com').fill(domain);
        // Use 'form select' to target the type dropdown in the create form,
        // not the PHP version selects in existing site rows
        const typeSelect = this.page.locator('form select').first();
        await typeSelect.selectOption(siteType);
        await this.addSiteButton.click();
        await this.page.waitForLoadState('networkidle');
    }

    async deleteSite(domain: string) {
        // Use getByRole('row') to uniquely target the site row by domain text
        const row = this.page.getByRole('row').filter({ hasText: domain }).first();
        await row.getByRole('button', { name: 'Delete' }).click();
        // Inline confirmation: click "Yes" to confirm
        await this.page.getByRole('button', { name: 'Yes' }).click();
        await this.page.waitForLoadState('networkidle');
    }
}
