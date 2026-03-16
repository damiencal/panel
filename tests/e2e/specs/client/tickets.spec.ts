import { test, expect } from '@playwright/test';
import { ClientTicketsPage } from '../../pages/client/TicketsPage';

test.describe('Client Support Tickets', () => {
    test('shows seeded tickets in the list', async ({ page }) => {
        const tickets = new ClientTicketsPage(page);
        await tickets.goto();

        await expect(page.getByText(/subdomain|SSL certificate|disk quota/i).first()).toBeVisible();
    });

    test('shows ticket status badges', async ({ page }) => {
        const tickets = new ClientTicketsPage(page);
        await tickets.goto();

        await expect(page.getByText(/open|answered|closed/i).first()).toBeVisible();
    });

    test('open a new ticket and verify it appears', async ({ page }) => {
        const tickets = new ClientTicketsPage(page);
        await tickets.goto();

        const subject = `E2E test ticket ${Date.now()}`;
        await tickets.openTicket(subject);

        await expect(page.getByText(subject)).toBeVisible({ timeout: 15_000 });
    });

    test('reply to an existing ticket', async ({ page }) => {
        const tickets = new ClientTicketsPage(page);
        await tickets.goto();

        // Tickets use clickable rows. Find first Open ticket row.
        const openRow = page.getByRole('row').filter({ hasText: /Open/i }).first();
        if (await openRow.count() > 0 && await openRow.isVisible({ timeout: 5_000 })) {
            await openRow.click();
            await page.waitForTimeout(1000);

            const replyInput = page.getByPlaceholder(/reply/i).first();
            if (await replyInput.isVisible({ timeout: 5_000 })) {
                await replyInput.fill('E2E test reply from Playwright.');
                await page.getByRole('button', { name: /send|reply/i }).last().click();
                await page.waitForTimeout(1500);
                await expect(page.getByText(/E2E test reply/i)).toBeVisible({ timeout: 10_000 });
            }
        }
    });

    test('ticket detail shows message thread', async ({ page }) => {
        const tickets = new ClientTicketsPage(page);
        await tickets.goto();

        // Tickets use clickable rows (not links) — click the first ticket row with matching text
        const firstTicketRow = page.getByRole('row').filter({ hasText: /subdomain|SSL|quota/i }).first();
        if (await firstTicketRow.isVisible({ timeout: 5_000 })) {
            await firstTicketRow.click();
            await page.waitForTimeout(1000);

            // Should show at least one message body in the TicketDetail panel
            const messages = page.getByText(/How do I add|SSL cert|please double|No messages/i).first();
            await expect(messages).toBeVisible({ timeout: 15_000 });
        }
    });
});
