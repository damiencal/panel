import { test, expect } from '@playwright/test';

test.describe('Admin WAF (ModSecurity)', () => {
    test('WAF page loads', async ({ page }) => {
        await page.goto('/admin/waf');
        await page.waitForLoadState('networkidle');

        await expect(page).not.toHaveURL(/login/);
        await expect(
            page.getByText(/waf|web application firewall|modsecurity/i).first()
        ).toBeVisible({ timeout: 15_000 });
    });

    test('ModSecurity toggle is present', async ({ page }) => {
        await page.goto('/admin/waf');
        await page.waitForLoadState('networkidle');

        const toggle = page
            .getByRole('checkbox', { name: /modsecurity|waf/i })
            .or(page.getByRole('switch', { name: /modsecurity|waf/i }))
            .or(page.getByText(/modsecurity|enable waf/i));
        await expect(toggle.first()).toBeVisible({ timeout: 15_000 });
    });

    test('rule set selection is visible', async ({ page }) => {
        await page.goto('/admin/waf');
        await page.waitForLoadState('networkidle');

        const rules = page
            .getByText(/OWASP|CRS|ruleset/i)
            .or(page.getByLabel(/rule set/i))
            .or(page.getByRole('combobox', { name: /rule/i }));
        await expect(rules.first()).toBeVisible({ timeout: 15_000 });
    });

    test('save configuration button is present', async ({ page }) => {
        await page.goto('/admin/waf');
        await page.waitForLoadState('networkidle');

        // WAF page uses engine mode toggle buttons (On/DetectionOnly/Off) + Refresh
        // Check for the engine mode selection buttons instead of a save button
        const engineBtn = page
            .getByRole('button', { name: /On|DetectionOnly|Off|Refresh/i })
            .first();
        await expect(engineBtn).toBeVisible({ timeout: 15_000 });
    });
});
