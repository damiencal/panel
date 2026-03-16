/**
 * pages/reseller/ResellerDashboardPage.ts
 */
import { Page, Locator } from '@playwright/test';

export class ResellerDashboardPage {
    readonly clientCount: Locator;
    readonly usageSummary: Locator;

    constructor(private readonly page: Page) {
        this.clientCount = page.locator('text=/\\d+ client/i').first();
        this.usageSummary = page.locator('[class*="usage"], [class*="quota"]').first();
    }

    async goto() {
        await this.page.goto('/reseller');
        await this.page.waitForLoadState('networkidle');
    }
}
