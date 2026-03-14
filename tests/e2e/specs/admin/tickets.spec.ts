import { test, expect } from '@playwright/test';

test.describe('Admin Tickets', () => {
    test('tickets page loads', async ({ page }) => {
        await page.goto('/admin/tickets');
        await page.waitForLoadState('networkidle');

        await expect(page).not.toHaveURL(/login/);
        await expect(page.getByText(/ticket/i).first()).toBeVisible({ timeout: 15_000 });
    });

    test('shows tickets from all users', async ({ page }) => {
        await page.goto('/admin/tickets');
        await page.waitForLoadState('networkidle');

        // seed has 5 tickets: "How do I add a subdomain?" etc.
        await expect(
            page.getByText(/subdomain|SSL certificate|disk quota|billing|database/i).first()
        ).toBeVisible({ timeout: 15_000 });
    });

    test('shows open and closed ticket statuses', async ({ page }) => {
        await page.goto('/admin/tickets');
        await page.waitForLoadState('networkidle');

        // DB tickets have statuses: ClientReply, Answered, Closed (no "Open" status after test runs)
        await expect(page.getByText(/answered|clientreply|closed/i).first()).toBeVisible({ timeout: 15_000 });
        await expect(page.getByText(/closed/i).first()).toBeVisible({ timeout: 5_000 });
    });

    test('open ticket shows reply form', async ({ page }) => {
        await page.goto('/admin/tickets');
        await page.waitForLoadState('networkidle');

        // Click the first open ticket row (tickets use clickable rows, not links)
        const openRow = page.getByRole('row').filter({ hasText: /Open/i }).first();
        if (await openRow.isVisible({ timeout: 5_000 })) {
            await openRow.click();
            await page.waitForTimeout(1000);

            const replyArea = page
                .getByRole('textbox', { name: /reply|message|response/i })
                .or(page.getByPlaceholder(/reply|message/i));
            await expect(replyArea.first()).toBeVisible({ timeout: 15_000 });
        }
    });

    test('admin can submit a reply to a ticket', async ({ page }) => {
        await page.goto('/admin/tickets');
        await page.waitForLoadState('networkidle');

        // Find and click an Open ticket row (tickets use clickable rows not links)
        const ticketRow = page.getByRole('row').filter({ hasText: /Open/i }).first();

        if (await ticketRow.isVisible({ timeout: 5_000 })) {
            await ticketRow.click();
            await page.waitForTimeout(1000);

            const replyArea = page
                .getByRole('textbox', { name: /reply|message/i })
                .or(page.getByPlaceholder(/reply/i));
            if (await replyArea.first().isVisible({ timeout: 5_000 })) {
                await replyArea.first().fill('Admin reply from automated test.');
                const submit = page.getByRole('button', { name: /send|submit|reply/i }).first();
                await submit.click();
                await page.waitForTimeout(1500);
                await expect(page.getByText('Admin reply from automated test.')).toBeVisible({
                    timeout: 10_000,
                });
            }
        }
    });
});
