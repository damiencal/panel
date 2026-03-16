/**
 * pages/reseller/BrandingPage.ts
 */
import { Page, Locator } from '@playwright/test';

export class ResellerBrandingPage {
    readonly panelNameInput: Locator;
    readonly accentColorInput: Locator;
    readonly customDomainInput: Locator;
    readonly saveButton: Locator;

    constructor(private readonly page: Page) {
        this.panelNameInput = page.getByLabel(/panel name/i);
        this.accentColorInput = page.getByLabel(/accent color|primary color/i);
        this.customDomainInput = page.getByLabel(/custom domain/i);
        this.saveButton = page.getByRole('button', { name: /save|update/i }).last();
    }

    async goto() {
        await this.page.goto('/reseller/branding');
        await this.page.waitForLoadState('networkidle');
    }

    async updateBranding(panelName: string, accentColor: string) {
        await this.panelNameInput.clear();
        await this.panelNameInput.fill(panelName);
        const colorField = this.accentColorInput;
        if (await colorField.count() > 0) {
            await colorField.fill(accentColor);
        }
        await this.saveButton.click();
        await this.page.waitForLoadState('networkidle');
    }
}
