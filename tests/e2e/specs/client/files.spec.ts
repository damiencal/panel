import { test, expect } from '@playwright/test';
import { ClientFileManagerPage } from '../../pages/client/FileManagerPage';
import path from 'path';
import fs from 'fs';
import os from 'os';

test.describe('Client File Manager', () => {
    test('loads file manager and shows root listing', async ({ page }) => {
        const fm = new ClientFileManagerPage(page);
        await fm.goto();

        // Should show a site selector or a file listing
        const listing = page.locator('select, table, [class*="file-list"], [class*="directory"]').first();
        await expect(listing).toBeVisible({ timeout: 15_000 });
    });

    test('shows index.html in root of wp.panel.test', async ({ page }) => {
        const fm = new ClientFileManagerPage(page);
        await fm.goto();
        await fm.selectSite('wp.panel.test');

        // The seeded site should have an index.html or WordPress files
        const fileEntry = page.getByText(/index\.(html|php)|wp-config|wp-content/i).first();
        await expect(fileEntry).toBeVisible({ timeout: 10_000 });
    });

    test('create a folder and verify it appears', async ({ page }) => {
        const fm = new ClientFileManagerPage(page);
        await fm.goto();
        await fm.selectSite('wp.panel.test');

        const folderName = `pw-folder-${Date.now()}`;
        await fm.createFolder(folderName);

        await expect(page.getByText(folderName)).toBeVisible({ timeout: 10_000 });

        // Clean up
        await fm.deleteItem(folderName);
        await expect(page.getByText(folderName)).not.toBeVisible({ timeout: 10_000 });
    });

    test('upload a file and verify it appears', async ({ page }) => {
        const fm = new ClientFileManagerPage(page);
        await fm.goto();
        await fm.selectSite('wp.panel.test');

        // Create a temp file to upload
        const tmpFile = path.join(os.tmpdir(), `pw-upload-${Date.now()}.txt`);
        fs.writeFileSync(tmpFile, 'Playwright test upload');

        try {
            await fm.uploadFile(tmpFile);
            const fileName = path.basename(tmpFile);
            await expect(page.getByText(fileName)).toBeVisible({ timeout: 15_000 });

            // Clean up
            await fm.deleteItem(fileName);
        } finally {
            fs.unlinkSync(tmpFile);
        }
    });

    test('breadcrumb shows root / on initial load', async ({ page }) => {
        const fm = new ClientFileManagerPage(page);
        await fm.goto();
        await fm.selectSite('wp.panel.test');

        // Breadcrumb is a <nav> element with "Home" as the root button
        const breadcrumb = page.locator('nav').filter({ hasText: /home/i }).first();
        await expect(breadcrumb).toBeVisible({ timeout: 10_000 });
    });
});
