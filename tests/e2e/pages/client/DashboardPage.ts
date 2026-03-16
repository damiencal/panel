/**
 * pages/client/DashboardPage.ts
 */
import { Page, Locator } from '@playwright/test';

export class ClientDashboardPage {
    readonly heading: Locator;
    readonly quotaWidgets: Locator;
    readonly siteCountBadge: Locator;

    constructor(private readonly page: Page) {
        this.heading = page.getByRole('heading', { name: /welcome back|my hosting/i }).first();
        this.quotaWidgets = page.locator('p').filter({ hasText: /websites|databases|email domains|open tickets/i });
        this.siteCountBadge = page.locator('p').filter({ hasText: 'Websites' }).first();
    }

    async goto() {
        await this.page.goto('/');
        await this.page.waitForLoadState('networkidle');
    }
}
