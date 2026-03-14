import { chromium } from '@playwright/test';
import fs from 'fs';

async function main() {
    const TOKEN = fs.readFileSync('/workspaces/web.com.do/tests/e2e/.auth/client.json', 'utf-8');
    const cookies = JSON.parse(TOKEN).cookies;

    const browser = await chromium.launch({ headless: true });
    const ctx = await browser.newContext();
    await ctx.addCookies(cookies);
    const page = await ctx.newPage();

    await page.goto('http://localhost:8080/');
    // Wait for WASM to load and render
    await page.waitForTimeout(8000);

    // Look for headings
    const headings = await page.locator('h1, h2, h3, h4').allTextContents();
    console.log('Headings:', JSON.stringify(headings));

    // Look for navigation text
    const navText = await page.locator('nav, [role="navigation"]').allTextContents();
    console.log('Nav text:', JSON.stringify(navText.join('').slice(0, 200)));

    // Get body text snapshot
    const bodyText = await page.locator('body').textContent();
    console.log('Body text (first 600 chars):', bodyText?.slice(0, 600));

    await browser.close();
}

main().catch(console.error);
