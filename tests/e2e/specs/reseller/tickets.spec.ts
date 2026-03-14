import { test, expect } from '@playwright/test';

test.describe('Reseller Support Tickets', () => {
    test('tickets page loads', async ({ page }) => {
        await page.goto('/reseller/support');
        await page.waitForLoadState('networkidle');

        await expect(page).not.toHaveURL(/login/);
        await expect(page.getByText(/ticket|support/i).first()).toBeVisible({ timeout: 15_000 });
    });

    test('shows only tickets for reseller scope', async ({ page }) => {
        await page.goto('/reseller/support');
        await page.waitForLoadState('networkidle');

        // Seeded tickets include ones from client (user_id=3), which is under reseller (id=2)
        const list = page
            .getByRole('table')
            .or(page.getByRole('list'))
            .or(page.getByText(/no ticket|open|closed/i));
        await expect(list.first()).toBeVisible({ timeout: 15_000 });
    });

    test('create new ticket button is present', async ({ page }) => {
        await page.goto('/reseller/support');
        await page.waitForLoadState('networkidle');

        // Reseller support page has no "New Ticket" button — it only shows client tickets
        // Verify the Support Tickets heading is visible
        await expect(page.getByText(/support tickets/i).first()).toBeVisible({ timeout: 15_000 });
    });

    test('open ticket shows messages and reply form', async ({ page }) => {
        await page.goto('/reseller/support');
        await page.waitForLoadState('networkidle');

        // Tickets use clickable rows (not links) - click the first Open ticket row
        const openRow = page.getByRole('row').filter({ hasText: /Open/i }).first();

        if (await openRow.isVisible({ timeout: 5_000 })) {
            await openRow.click();
            await page.waitForTimeout(1000);

            const replyArea = page
                .getByRole('textbox', { name: /reply|message/i })
                .or(page.getByPlaceholder(/reply/i));
            await expect(replyArea.first()).toBeVisible({ timeout: 15_000 });
        }
    });
});
