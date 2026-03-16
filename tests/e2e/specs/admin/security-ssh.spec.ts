import { test, expect } from '@playwright/test';

test.describe('Admin SSH Hardening', () => {
    test('SSH hardening page loads', async ({ page }) => {
        await page.goto('/admin/ssh-hardening');
        await page.waitForLoadState('networkidle');

        await expect(page).not.toHaveURL(/login/);
        await expect(
            page.getByText(/ssh|hardening/i).first()
        ).toBeVisible({ timeout: 15_000 });
    });

    test('password authentication toggle is visible', async ({ page }) => {
        await page.goto('/admin/ssh-hardening');
        await page.waitForLoadState('networkidle');

        const toggle = page
            .getByText(/password auth|PasswordAuthentication/i)
            .or(page.getByRole('checkbox', { name: /password/i }))
            .or(page.getByRole('switch', { name: /password/i }));
        await expect(toggle.first()).toBeVisible({ timeout: 15_000 });
    });

    test('root login toggle is visible', async ({ page }) => {
        await page.goto('/admin/ssh-hardening');
        await page.waitForLoadState('networkidle');

        const rootToggle = page
            .getByText(/root login|PermitRootLogin/i)
            .or(page.getByRole('checkbox', { name: /root/i }));
        await expect(rootToggle.first()).toBeVisible({ timeout: 15_000 });
    });

    test('SSH port configuration is present', async ({ page }) => {
        await page.goto('/admin/ssh-hardening');
        await page.waitForLoadState('networkidle');

        // The "SSH Port" label text is visible (label is adjacent to input, not wrapping it)
        // Check for the label text OR the input number directly
        const portLabel = page.getByText(/ssh port/i).first();
        await expect(portLabel).toBeVisible({ timeout: 15_000 });
    });

    test('save / apply button is present', async ({ page }) => {
        await page.goto('/admin/ssh-hardening');
        await page.waitForLoadState('networkidle');

        const save = page.getByRole('button', { name: /save|apply|update/i }).first();
        await expect(save).toBeVisible({ timeout: 15_000 });
    });
});
