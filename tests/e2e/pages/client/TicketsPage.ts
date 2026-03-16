/**
 * pages/client/TicketsPage.ts
 */
import { Page, Locator } from '@playwright/test';

export class ClientTicketsPage {
    readonly newTicketButton: Locator;

    constructor(private readonly page: Page) {
        this.newTicketButton = page.getByRole('button', { name: /new ticket|open ticket|create ticket/i });
    }

    async goto() {
        await this.page.goto('/support');
        await this.page.waitForLoadState('networkidle');
    }

    async openTicket(subject: string) {
        await this.newTicketButton.click();
        // Use placeholders — Dioxus labels are adjacent siblings (not wrapping), so getByLabel fails
        await this.page.getByPlaceholder('Brief description of your issue').fill(subject);
        await this.page.getByPlaceholder('Describe your issue in detail...').fill('Test message from Playwright E2E.');
        await this.page.getByRole('button', { name: /submit ticket/i }).click();
        await this.page.waitForLoadState('networkidle');
    }

    async replyToTicket(subject: string, reply: string) {
        await this.page.getByRole('link', { name: subject }).first().click();
        await this.page.getByLabel(/reply|message/i).fill(reply);
        await this.page.getByRole('button', { name: /send|reply|submit/i }).last().click();
        await this.page.waitForLoadState('networkidle');
    }

    async closeTicket(subject: string) {
        await this.page.getByRole('link', { name: subject }).first().click();
        await this.page.getByRole('button', { name: /close ticket/i }).click();
        await this.page.waitForLoadState('networkidle');
    }
}
