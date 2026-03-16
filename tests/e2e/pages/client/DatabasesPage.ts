/**
 * pages/client/DatabasesPage.ts
 */
import { Page, Locator } from '@playwright/test';

export class ClientDatabasesPage {
    readonly addDbButton: Locator;

    constructor(private readonly page: Page) {
        this.addDbButton = page.getByRole('button', { name: /add|new|create/i }).first();
    }

    async goto() {
        await this.page.goto('/databases');
        await this.page.waitForLoadState('networkidle');
    }

    async createDatabase(name: string) {
        // Create form is always visible (no toggle button needed)
        await this.page.getByPlaceholder('my_database').fill(name);
        await this.page.getByRole('button', { name: /^create$/i }).last().click();
        await this.page.waitForLoadState('networkidle');
    }

    async deleteDatabase(name: string) {
        const row = this.page.locator(`tr:has-text("${name}"), [class*="row"]:has-text("${name}")`).first();
        await row.getByRole('button', { name: /delete|remove/i }).click();
        // Must type "DELETE" in the confirmation input before the button activates
        await this.page.getByPlaceholder('DELETE').fill('DELETE');
        await this.page.getByRole('button', { name: /delete database/i }).click();
        await this.page.waitForLoadState('networkidle');
    }
}
