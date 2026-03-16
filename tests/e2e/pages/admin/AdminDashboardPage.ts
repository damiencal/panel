/**
 * pages/admin/AdminDashboardPage.ts
 */
import { Page, Locator } from '@playwright/test';

export class AdminDashboardPage {
    readonly serviceStatusCards: Locator;
    readonly serverMetrics: Locator;

    constructor(private readonly page: Page) {
        // Admin dashboard shows stat cards: Total Users, Resellers, Clients, Sites
        this.serviceStatusCards = page.locator('p').filter({ hasText: /total users|clients|resellers|sites/i });
        this.serverMetrics = page.locator('p').filter({ hasText: /total users|resellers/i });
    }

    async goto() {
        await this.page.goto('/admin');
        await this.page.waitForLoadState('networkidle');
    }
}
