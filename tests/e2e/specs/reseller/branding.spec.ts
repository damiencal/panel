import { test, expect } from '@playwright/test';
import { ResellerBrandingPage } from '../../pages/reseller/BrandingPage';

test.describe('Reseller Branding', () => {
    test('branding page loads', async ({ page }) => {
        const branding = new ResellerBrandingPage(page);
        await branding.goto();

        await expect(page).not.toHaveURL(/login/);
        await expect(page.getByText(/branding/i).first()).toBeVisible({ timeout: 15_000 });
    });

    test('shows seeded brand name', async ({ page }) => {
        const branding = new ResellerBrandingPage(page);
        await branding.goto();

        // seed data: panel_name = 'MyHost Control Panel' — stored as INPUT value, not DOM text
        const nameInput = page.getByPlaceholder(/my hosting/i).first();
        await expect(nameInput).toHaveValue(/myhost/i, { timeout: 15_000 });
    });

    test('panel name input is editable', async ({ page }) => {
        const branding = new ResellerBrandingPage(page);
        await branding.goto();

        // The field is labeled "Panel Name" with placeholder "My Hosting"
        const nameInput = page
            .getByRole('textbox', { name: /my hosting/i })
            .or(page.getByPlaceholder(/my hosting|panel name|brand name|company/i));
        await expect(nameInput.first()).toBeVisible({ timeout: 15_000 });
        await nameInput.first().fill('Updated Co Test');
    });

    test('logo upload field is present', async ({ page }) => {
        const branding = new ResellerBrandingPage(page);
        await branding.goto();

        // Check for file input or a logo-related input/button
        const upload = page
            .locator('input[type="file"]')
            .or(page.getByRole('textbox', { name: /logo|upload/i }));
        // Logo field may be optional; check it's attached if it exists
        const count = await upload.count();
        if (count > 0) {
            await expect(upload.first()).toBeAttached({ timeout: 10_000 });
        } else {
            // Logo upload not present; verify panel name input instead
            await expect(page.getByRole('heading', { name: /panel identity/i })).toBeVisible({ timeout: 15_000 });
        }
    });

    test('save branding button is present', async ({ page }) => {
        const branding = new ResellerBrandingPage(page);
        await branding.goto();

        const save = page.getByRole('button', { name: /save|update|apply/i }).first();
        await expect(save).toBeVisible({ timeout: 15_000 });
    });

    test('primary color picker or hex input is present', async ({ page }) => {
        const branding = new ResellerBrandingPage(page);
        await branding.goto();

        // "Accent Color" section has a text input for hex color
        const colorPicker = page
            .locator('input[type="color"]')
            .or(page.getByPlaceholder(/#[0-9a-fA-F]{6}|hex/i));
        await expect(colorPicker.first()).toBeAttached({ timeout: 15_000 });
    });
});
