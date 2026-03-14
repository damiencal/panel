/**
 * pages/client/FileManagerPage.ts
 */
import { Page, Locator } from '@playwright/test';
import path from 'path';

export class ClientFileManagerPage {
    readonly breadcrumb: Locator;
    readonly newFolderButton: Locator;
    readonly uploadTrigger: Locator;

    constructor(private readonly page: Page) {
        // The breadcrumb is a <nav> element (no "breadcrumb" class)
        this.breadcrumb = page.locator('nav').first();
        this.newFolderButton = page.getByRole('button', { name: /new folder|create folder/i }).first();
        // Upload trigger is a <label> element containing the file input (not a button)
        this.uploadTrigger = page.locator('label').filter({ hasText: /upload/i }).first();
    }

    async goto() {
        await this.page.goto('/files');
        await this.page.waitForLoadState('networkidle');
    }

    /** Select a site from the site dropdown / selector. */
    async selectSite(domain: string) {
        const siteSelector = this.page.locator('select').first();
        await siteSelector.selectOption({ label: domain });
        await this.page.waitForLoadState('networkidle');
    }

    async navigateToFolder(name: string) {
        await this.page.getByText(name).first().click();
        await this.page.waitForLoadState('networkidle');
    }

    async createFolder(name: string) {
        await this.newFolderButton.click();
        await this.page.waitForTimeout(500);
        // New Folder dialog has input with placeholder "folder-name" (no label)
        await this.page.getByPlaceholder('folder-name').fill(name);
        await this.page.getByRole('button', { name: /^create$/i }).last().click();
        await this.page.waitForLoadState('networkidle');
    }

    /** Upload a file using the hidden file input inside the Upload label. */
    async uploadFile(localFilePath: string) {
        const [fileChooser] = await Promise.all([
            this.page.waitForEvent('filechooser'),
            this.uploadTrigger.click(),
        ]);
        await fileChooser.setFiles(localFilePath);
        await this.page.waitForLoadState('networkidle');
    }

    async deleteItem(name: string) {
        const row = this.page.locator(`tr:has-text("${name}"), [class*="entry"]:has-text("${name}")`).first();
        await row.getByRole('button', { name: /delete/i }).click();
        // Confirm dialog has a "Delete" button
        await this.page.getByRole('button', { name: /^delete$/i }).last().click();
        await this.page.waitForLoadState('networkidle');
    }
}
