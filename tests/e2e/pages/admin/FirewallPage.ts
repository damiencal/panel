/**
 * pages/admin/FirewallPage.ts
 */
import { Page, Locator } from '@playwright/test';

export class AdminFirewallPage {
    readonly addRuleButton: Locator;
    readonly rulesTable: Locator;

    constructor(private readonly page: Page) {
        this.addRuleButton = page.getByRole('button', { name: /add rule|new rule/i });
        this.rulesTable = page.locator('table').first();
    }

    async goto() {
        await this.page.goto('/admin/firewall');
        await this.page.waitForLoadState('networkidle');
    }

    async addAllowRule(port: string, comment: string) {
        await this.addRuleButton.click();
        // Action
        const actionSelect = this.page.getByLabel(/action/i);
        if (await actionSelect.count() > 0) await actionSelect.selectOption('allow');
        // Port
        await this.page.getByLabel(/port/i).fill(port);
        // Comment
        const commentField = this.page.getByLabel(/comment|description/i);
        if (await commentField.count() > 0) await commentField.fill(comment);
        await this.page.getByRole('button', { name: /save|add|create/i }).last().click();
        await this.page.waitForLoadState('networkidle');
    }

    async deleteRule(identifier: string) {
        const row = this.page.locator(`tr:has-text("${identifier}")`).first();
        await row.getByRole('button', { name: /delete|remove/i }).click();
        await this.page.getByRole('button', { name: /confirm|yes/i }).last().click();
        await this.page.waitForLoadState('networkidle');
    }
}
