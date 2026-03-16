/**
 * global-setup.ts
 *
 * Performs one login per role and saves the browser storage state
 * (cookies + localStorage) to .auth/{role}.json.
 *
 * Playwright projects reference these files via `storageState` so every
 * spec starts pre-authenticated — no redundant login requests.
 */
import { chromium, FullConfig } from '@playwright/test';
import fs from 'fs';
import path from 'path';
import { STORAGE_STATE } from './playwright.config';

interface LoginCredentials {
    username: string;
    password: string;
    expectedPath: string;
    stateFile: string;
}

const BASE_URL = process.env.PANEL_URL ?? 'http://localhost:8080';

const ROLES: LoginCredentials[] = [
    {
        username: 'admin',
        password: 'TestPass123!',
        expectedPath: '/admin',
        stateFile: STORAGE_STATE.admin,
    },
    {
        username: 'reseller',
        password: 'TestPass123!',
        expectedPath: '/reseller',
        stateFile: STORAGE_STATE.reseller,
    },
    {
        username: 'client',
        password: 'TestPass123!',
        expectedPath: '/',
        stateFile: STORAGE_STATE.client,
    },
];

async function loginAs(
    browser: ReturnType<typeof chromium.launch> extends Promise<infer T> ? T : never,
    creds: LoginCredentials,
): Promise<void> {
    const context = await browser.newContext({ ignoreHTTPSErrors: true });
    const page = await context.newPage();

    console.log(`[global-setup] Logging in as '${creds.username}'...`);

    await page.goto(`${BASE_URL}/login`);

    // Wait for Dioxus WASM to fully hydrate the page before interacting.
    // The WASM script is async - we wait for networkidle (all assets fetched)
    // and then for the hydration_callback to be registered by the WASM runtime.
    await page.waitForLoadState('networkidle', { timeout: 60_000 });
    // Dioxus WASM sets window.hydration_callback once the wasm module is ready
    await page.waitForFunction(
        () => typeof (window as any).hydration_callback === 'function',
        null,
        { timeout: 60_000 },
    );

    // Fill credentials — labels exist but are not associated via for/id,
    // so we target inputs by placeholder text (as rendered by the panel).
    await page.getByPlaceholder(/username/i).fill(creds.username);
    await page.getByPlaceholder(/password/i).fill(creds.password);
    await page.getByRole('button', { name: /sign in|log in/i }).click();

    // Wait until the router navigates away from /login to indicate success.
    // The dashboard loads async (WASM hydration), so we wait for a stable selector.
    await page.waitForURL(
        (url) => !url.pathname.includes('/login'),
        { timeout: 30_000 },
    );

    console.log(`[global-setup]  ✓ '${creds.username}' logged in → ${page.url()}`);

    // Ensure .auth directory exists
    fs.mkdirSync(path.dirname(creds.stateFile), { recursive: true });

    // Save cookies + localStorage
    await context.storageState({ path: creds.stateFile });
    await context.close();
}

export default async function globalSetup(_config: FullConfig): Promise<void> {
    const browser = await chromium.launch({ headless: true });

    // Sequential logins to avoid hammering the rate limiter
    for (const creds of ROLES) {
        await loginAs(browser, creds);
    }

    await browser.close();
    console.log('[global-setup] All auth states saved.');
}
