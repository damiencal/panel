/**
 * pages/admin/UsersPage.ts
 */
import { Page, Locator } from '@playwright/test';

export class AdminUsersPage {
    constructor(private readonly page: Page) { }

    async gotoClients() {
        await this.page.goto('/admin/clients');
        await this.page.waitForLoadState('networkidle');
    }

    async gotoResellers() {
        await this.page.goto('/admin/resellers');
        await this.page.waitForLoadState('networkidle');
    }

    async impersonateUser(username: string) {
        const row = this.page.locator(`tr:has-text("${username}")`).first();
        await row.getByRole('button', { name: /impersonate|login as/i }).click();
        // Should redirect to the target user's dashboard
        await this.page.waitForLoadState('networkidle');
    }

    async suspendUser(username: string) {
        const row = this.page.locator(`tr:has-text("${username}")`).first();
        await row.getByRole('button', { name: /suspend/i }).click();
        await this.page.getByRole('button', { name: /confirm|yes/i }).last().click();
        await this.page.waitForLoadState('networkidle');
    }

    async activateUser(username: string) {
        const row = this.page.locator(`tr:has-text("${username}")`).first();
        await row.getByRole('button', { name: /activate|unsuspend/i }).click();
        await this.page.waitForLoadState('networkidle');
    }
}
