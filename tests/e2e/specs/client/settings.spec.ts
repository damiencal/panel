import { test, expect } from '@playwright/test';
import { ClientSettingsPage } from '../../pages/client/SettingsPage';

test.describe('Client Settings — password', () => {
    test('password change form is visible', async ({ page }) => {
        const settings = new ClientSettingsPage(page);
        await settings.goto();

        // Password form is revealed by clicking "Change Password" button
        const changeBtn = page.getByRole('button', { name: /change password/i }).first();
        await expect(changeBtn).toBeVisible();
        await changeBtn.click();
        await expect(page.getByPlaceholder('Current password')).toBeVisible();
        await expect(page.getByPlaceholder('New password (12+ chars)')).toBeVisible();
    });

    test('rejects password change with wrong current password', async ({ page }) => {
        const settings = new ClientSettingsPage(page);
        await settings.goto();

        await settings.changePassword('WrongPasword', 'NewPass12345!');

        // Should show an error message
        const error = page.getByText(/incorrect|wrong|invalid|mismatch|characters/i).first();
        await expect(error).toBeVisible({ timeout: 10_000 });
    });
});

test.describe('Client Settings — 2FA', () => {
    test('2FA setup section is visible', async ({ page }) => {
        const settings = new ClientSettingsPage(page);
        await settings.goto();

        const twoFaSection = page.getByText(/two.factor|2fa|authenticator/i).first();
        await expect(twoFaSection).toBeVisible();
    });

    test('2FA enable button/link is accessible', async ({ page }) => {
        const settings = new ClientSettingsPage(page);
        await settings.goto();

        const enableBtn = page.getByRole('button', { name: /enable two.factor|two.factor auth/i }).first();
        await expect(enableBtn).toBeVisible();
    });

    test('clicking 2FA setup shows QR code or secret', async ({ page }) => {
        const settings = new ClientSettingsPage(page);
        await settings.goto();
        await settings.open2FASetup();

        const qrOrSecret = page.locator('img[alt*="qr"], canvas, [class*="qr"]')
            .or(page.getByText(/scan.*qr|secret key|TOTP/i)).first();
        await expect(qrOrSecret).toBeVisible({ timeout: 10_000 });
    });
});

test.describe('Client Settings — team', () => {
    test('security section is visible', async ({ page }) => {
        const settings = new ClientSettingsPage(page);
        await settings.goto();

        // Settings page has a Security section with password change and 2FA options
        const securitySection = page.getByRole('heading', { name: /security/i }).first();
        await expect(securitySection).toBeVisible();
    });
});
