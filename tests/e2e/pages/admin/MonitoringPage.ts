/**
 * pages/admin/MonitoringPage.ts
 */
import { Page, Locator } from '@playwright/test';

export class AdminMonitoringPage {
    readonly cpuMetric: Locator;
    readonly memoryMetric: Locator;
    readonly processTable: Locator;

    constructor(private readonly page: Page) {
        this.cpuMetric = page.locator('[class*="cpu"], text=/cpu/i').first();
        this.memoryMetric = page.locator('[class*="mem"], text=/memory|ram/i').first();
        this.processTable = page.locator('table:has(th:has-text("PID")), table:has(th:has-text("Process"))').first();
    }

    async goto() {
        await this.page.goto('/admin/monitoring');
        await this.page.waitForLoadState('networkidle');
    }

    async killProcess(pid: number) {
        const row = this.page.locator(`tr:has-text("${pid}")`).first();
        await row.getByRole('button', { name: /kill|terminate/i }).click();
        await this.page.getByRole('button', { name: /confirm|yes/i }).last().click();
        await this.page.waitForLoadState('networkidle');
    }
}
