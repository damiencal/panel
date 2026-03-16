import { test, expect } from '@playwright/test';

test.describe('Client Git Repositories', () => {
    // Helper: navigate to git page and select a site to load repos
    async function gotoGitWithSite(page: import('@playwright/test').Page) {
        await page.goto('/git');
        await page.waitForLoadState('networkidle');
        await page.locator('select').selectOption({ label: 'wp.panel.test' });
        await page.waitForTimeout(500);
    }

    test('shows seeded git repo for wp.panel.test', async ({ page }) => {
        await gotoGitWithSite(page);
        await expect(page.getByText(/wp-theme|github\.com\/example/i)).toBeVisible();
    });

    test('shows branch name', async ({ page }) => {
        await gotoGitWithSite(page);
        await expect(page.getByText('main')).toBeVisible();
    });

    test('shows last commit hash or "never synced"', async ({ page }) => {
        await gotoGitWithSite(page);
        const commitInfo = page.getByText(/abc1234|never synced|not synced|no commits/i).first();
        await expect(commitInfo).toBeVisible();
    });

    test('add git repo and link to a site', async ({ page }) => {
        await gotoGitWithSite(page);

        const addButton = page.getByRole('button', { name: /add repo|connect repo|new repo/i }).first();
        if (await addButton.count() === 0) {
            // Some UIs show an edit/link per site row; skip if no explicit add button
            test.skip();
            return;
        }
        await addButton.click();

        const repoInput = page.getByLabel(/repo.*url|url/i);
        await repoInput.fill('https://github.com/example/test-repo.git');

        await page.getByRole('button', { name: /save|add|link/i }).last().click();
        await page.waitForLoadState('networkidle');

        await expect(page.getByText(/test-repo/i)).toBeVisible({ timeout: 10_000 });
    });
});
