import { defineConfig, devices } from '@playwright/test';
import path from 'path';

/**
 * Playwright configuration for the web.com.do panel E2E test suite.
 *
 * Three browser projects map to the three portal roles:
 *   client-portal   →  http://localhost:8080/
 *   admin-portal    →  http://localhost:8080/admin
 *   reseller-portal →  http://localhost:8080/reseller
 *
 * Each project uses a dedicated saved auth state (storageState) so login
 * only happens once in globalSetup, not before every spec.
 */

// Auth state files produced by globalSetup
export const STORAGE_STATE = {
    admin: path.join(__dirname, '.auth/admin.json'),
    reseller: path.join(__dirname, '.auth/reseller.json'),
    client: path.join(__dirname, '.auth/client.json'),
};

export default defineConfig({
    testDir: './specs',
    fullyParallel: true,
    forbidOnly: !!process.env.CI,
    retries: process.env.CI ? 2 : 0,
    workers: process.env.CI ? 4 : undefined,
    reporter: [
        ['list'],
        ['html', { outputFolder: '../../playwright-report', open: 'never' }],
        ...(process.env.CI ? [['github'] as ['github']] : []),
    ],

    use: {
        baseURL: process.env.PANEL_URL ?? 'http://localhost:8080',
        // Panel uses HttpOnly cookies for auth — capture them via storageState
        trace: 'on-first-retry',
        screenshot: 'only-on-failure',
        video: 'retain-on-failure',
        // Dioxus WASM apps need a little extra time to hydrate on first load
        actionTimeout: 15_000,
        navigationTimeout: 30_000,
    },

    // Run global setup once before all tests to perform login for each role
    globalSetup: require.resolve('./global-setup'),

    projects: [
        // ── Prerequisite: perform login for all three roles ────────────────────
        {
            name: 'setup',
            testMatch: /global-setup\.ts/,
        },

        // ── Client portal ──────────────────────────────────────────────────────
        {
            name: 'client-portal',
            testDir: './specs/client',
            use: {
                ...devices['Desktop Chrome'],
                storageState: STORAGE_STATE.client,
            },
            dependencies: ['setup'],
        },

        // ── Admin portal ───────────────────────────────────────────────────────
        {
            name: 'admin-portal',
            testDir: './specs/admin',
            use: {
                ...devices['Desktop Chrome'],
                storageState: STORAGE_STATE.admin,
            },
            dependencies: ['setup'],
        },

        // ── Reseller portal ────────────────────────────────────────────────────
        {
            name: 'reseller-portal',
            testDir: './specs/reseller',
            use: {
                ...devices['Desktop Chrome'],
                storageState: STORAGE_STATE.reseller,
            },
            dependencies: ['setup'],
        },
    ],

    // Start the sandbox container automatically when not already running
    // (Disabled in CI where the container is started by the workflow)
    ...(process.env.CI
        ? {}
        : {
            webServer: {
                command: 'docker compose -f sandbox/docker-compose.test.yml up --build',
                url: 'http://localhost:8080',
                reuseExistingServer: !process.env.CI,
                timeout: 600_000, // 10 min for first build
                stdout: 'pipe',
                stderr: 'pipe',
            },
        }),
});
