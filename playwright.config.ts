import { defineConfig } from '@playwright/test';

export default defineConfig({
  testDir: './playwright/tests',
  timeout: 60000,
  retries: process.env.CI ? 1 : 0,
  use: {
    baseURL: 'http://127.0.0.1:8000',
    headless: true,
  },
  webServer: {
    command: './start_dev.sh',
    url: 'http://127.0.0.1:8000',
    reuseExistingServer: !process.env.CI,
    timeout: 120000,
    env: {
      FIRE_FIND_API_TOKEN: 'e2e-test-token',
      FIRE_FIND_RULES_CONFIG: 'backend/rules/rules.yaml',
      FIRE_FIND_RULES_HISTORY: 'backend/rules/rules.history.jsonl',
    },
  },
});
