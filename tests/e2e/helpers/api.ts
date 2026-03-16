/**
 * helpers/api.ts
 *
 * Lightweight API helpers that call the panel's server endpoints directly
 * from test code (bypassing the browser UI). Used to create or clean up
 * test fixtures without having to navigate through the UI every time.
 *
 * The panel uses Dioxus server functions, which are POST requests to
 * /_dioxus/<fn_name> with a JSON-encoded positional argument array.
 *
 * For sandbox seed data these helpers are used sparingly — most data is
 * pre-seeded by seed-panel.sh. Use these helpers when a test needs to
 * create an ephemeral resource (e.g., create a ticket then assert it appears).
 */
import { APIRequestContext } from '@playwright/test';

const BASE_URL = process.env.PANEL_URL ?? 'http://localhost:8080';

/** POST to a Dioxus server function and return the parsed JSON response. */
export async function callServerFn(
    request: APIRequestContext,
    fnName: string,
    args: unknown[],
): Promise<unknown> {
    const url = `${BASE_URL}/_dioxus/${fnName}`;
    const resp = await request.post(url, {
        data: JSON.stringify(args),
        headers: { 'Content-Type': 'application/json' },
    });
    if (!resp.ok()) {
        throw new Error(`Server function '${fnName}' failed: ${resp.status()} ${await resp.text()}`);
    }
    return resp.json();
}

/** Quick helper: assert that a page has navigated away from /login. */
export function isAuthenticated(url: URL): boolean {
    return !url.pathname.includes('/login');
}
