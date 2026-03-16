/**
 * pages/LoginPage.ts — shared across all portal logins
 */
import { Page } from '@playwright/test';

export class LoginPage {
    constructor(private readonly page: Page) { }

    async goto() {
        await this.page.goto('/login');
    }

    async login(username: string, password: string) {
        // Labels are not associated via for/id; use placeholder-based selectors
        await this.page.getByPlaceholder(/username/i).fill(username);
        await this.page.getByPlaceholder(/password/i).fill(password);
        await this.page.getByRole('button', { name: /sign in|log in/i }).click();
        // Wait for navigation away from /login
        await this.page.waitForURL((url) => !url.pathname.includes('/login'), {
            timeout: 30_000,
        });
    }

    /** Fill TOTP code field when 2FA is required. */
    async fillTotp(code: string) {
        await this.page.getByLabel(/authenticator code|2fa|totp/i).fill(code);
        await this.page.getByRole('button', { name: /verify|continue/i }).click();
    }
}
