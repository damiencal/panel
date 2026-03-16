/**
 * pages/client/EmailPage.ts
 */
import { Page, Locator } from '@playwright/test';

export class ClientEmailPage {
    readonly addDomainButton: Locator;
    readonly addMailboxButton: Locator;
    readonly addForwarderButton: Locator;

    constructor(private readonly page: Page) {
        this.addDomainButton = page.getByRole('button', { name: /add domain|new domain/i }).first();
        this.addMailboxButton = page.getByRole('button', { name: /add mailbox|new mailbox/i }).first();
        this.addForwarderButton = page.getByRole('button', { name: /add forwarder|new forwarder/i }).first();
    }

    async goto() {
        await this.page.goto('/email');
        await this.page.waitForLoadState('networkidle');
    }

    async selectDomain(domain: string) {
        // Use exact text match to avoid clicking header username (e.g., "client@panel.test")
        await this.page.getByText(domain, { exact: true }).click();
        await this.page.waitForLoadState('networkidle');
    }

    async createMailbox(localPart: string, password: string) {
        await this.addMailboxButton.click();
        await this.page.getByLabel(/local part|username|email/i).fill(localPart);
        await this.page.getByLabel(/password/i).fill(password);
        await this.page.getByRole('button', { name: /create|save/i }).last().click();
        await this.page.waitForLoadState('networkidle');
    }

    async deleteMailbox(localPart: string) {
        const row = this.page.locator(`tr:has-text("${localPart}")`).first();
        await row.getByRole('button', { name: /delete/i }).click();
        await this.page.getByRole('button', { name: /confirm|yes|delete/i }).last().click();
        await this.page.waitForLoadState('networkidle');
    }

    async toggleDKIM(domain: string) {
        const row = this.page.locator(`tr:has-text("${domain}"), [class*="row"]:has-text("${domain}")`).first();
        const dkimToggle = row.getByRole('button', { name: /dkim/i })
            .or(row.locator('input[type="checkbox"]').first());
        await dkimToggle.click();
        await this.page.waitForLoadState('networkidle');
    }
}
