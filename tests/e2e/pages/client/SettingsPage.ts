/**
 * pages/client/SettingsPage.ts
 */
import { Page, Locator } from '@playwright/test';

export class ClientSettingsPage {
    constructor(private readonly page: Page) { }

    async goto() {
        await this.page.goto('/settings');
        await this.page.waitForLoadState('networkidle');
    }

    async changePassword(currentPass: string, newPass: string) {
        // Password form is behind a toggle button
        const toggleBtn = this.page.getByRole('button', { name: /change password/i }).first();
        if (await toggleBtn.isVisible()) await toggleBtn.click();
        // Use placeholders — Dioxus labels are adjacent siblings (not wrapping), so getByLabel fails
        await this.page.getByPlaceholder('Current password').fill(currentPass);
        await this.page.getByPlaceholder('New password (12+ chars)').fill(newPass);
        await this.page.getByPlaceholder(/confirm new password/i).fill(newPass);
        await this.page.getByRole('button', { name: /save password/i }).click();
        await this.page.waitForLoadState('networkidle');
    }

    async open2FASetup() {
        await this.page.getByRole('button', { name: /enable two.factor|two.factor auth/i }).click();
        await this.page.waitForTimeout(1000);
    }

    /** Invite a team member. */
    async inviteTeamMember(email: string) {
        await this.page.getByRole('button', { name: /invite|add team member/i }).click();
        await this.page.getByLabel(/email/i).fill(email);
        await this.page.getByRole('button', { name: /send invite|invite/i }).last().click();
        await this.page.waitForLoadState('networkidle');
    }
}
