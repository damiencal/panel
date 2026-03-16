import { chromium } from '@playwright/test';
import fs from 'fs';

async function main() {
    const TOKEN = fs.readFileSync('/workspaces/web.com.do/tests/e2e/.auth/client.json', 'utf-8');
    const storageState = JSON.parse(TOKEN);

    const browser = await chromium.launch({ headless: true });
    const ctx = await browser.newContext({ storageState });
    const page = await ctx.newPage();
    await page.goto('http://localhost:8080/');
    
    // Wait for content to appear
    await page.waitForSelector('nav a', { timeout: 15000 });
    
    const links = await page.getByRole('link').all();
    console.log('Total links found:', links.length);
    for (const link of links) {
        const text = await link.textContent();
        const name = await link.getAttribute('aria-label') || text;
        const href = await link.getAttribute('href');
        console.log(`  Link: name="${name?.trim()}" href="${href}"`);
    }
    
    // Test specific search
    const sitesLinks = await page.getByRole('link', { name: /Sites/i }).all();
    console.log(`Links matching /Sites/i: ${sitesLinks.length}`);
    
    const websitesLinks = await page.getByRole('link', { name: /Websites/i }).all();
    console.log(`Links matching /Websites/i: ${websitesLinks.length}`);
    
    const cronLinks = await page.getByRole('link', { name: /Cron/i }).all();
    console.log(`Links matching /Cron/i: ${cronLinks.length}`);
    
    // Check headings
    const headings = await page.getByRole('heading').all();
    console.log('\nHeadings:');
    for (const h of headings) {
        const text = await h.textContent();
        console.log(`  H: "${text?.trim()}"`);
    }
    
    await browser.close();
}

main().catch(console.error);
