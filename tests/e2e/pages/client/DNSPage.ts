/**
 * pages/client/DNSPage.ts
 */
import { Page, Locator } from '@playwright/test';

export class ClientDNSPage {
    readonly addZoneButton: Locator;
    readonly addRecordButton: Locator;

    constructor(private readonly page: Page) {
        this.addZoneButton = page.getByRole('button', { name: /add zone|new zone/i }).first();
        this.addRecordButton = page.getByRole('button', { name: /add record|new record/i }).first();
    }

    async goto() {
        await this.page.goto('/dns');
        await this.page.waitForLoadState('networkidle');
    }

    async selectZone(domain: string) {
        // Each zone is a glass-card div with an h3 heading and a "Manage Records" button.
        // Find the card div that contains this domain's h3, then click its button.
        await this.page.locator('div').filter({
            has: this.page.locator('h3', { hasText: new RegExp(`^${domain.replace('.', '\\.')}$`) })
        }).getByRole('button', { name: 'Manage Records' }).first().click();
        await this.page.waitForTimeout(500);
    }

    async addRecord(type: string, name: string, value: string) {
        await this.addRecordButton.click();
        // Target the Type select by filtering for the one that contains DNS record type options
        const typeSelect = this.page.locator('select').filter({
            has: this.page.locator('option[value="TXT"]'),
        }).first();
        await typeSelect.selectOption(type);
        // Name input has placeholder "@ or subdomain"
        await this.page.getByPlaceholder(/@ or subdomain/).fill(name);
        // Value placeholder changes by type — wait briefly for reactive update
        await this.page.waitForTimeout(200);
        // Fill the value input (placeholder varies: TXT="v=spf1...", A="192.168.1.1", etc.)
        const valueInput = this.page
            .getByPlaceholder(/v=spf1|192\.168|mail\.example|target\.example|2001:|ns1\.|10 [0-9]|0 issue/i)
            .or(this.page.getByPlaceholder(/^value$/i));
        await valueInput.first().fill(value);
        await this.page.getByRole('button', { name: 'Add Record' }).click();
        await this.page.waitForLoadState('networkidle');
    }

    async deleteRecord(name: string) {
        const row = this.page.locator(`tr:has-text("${name}")`).first();
        await row.getByRole('button', { name: /delete|remove/i }).click();
        // No confirmation dialog — deletion is immediate in this UI
        await this.page.waitForLoadState('networkidle');
    }
}
