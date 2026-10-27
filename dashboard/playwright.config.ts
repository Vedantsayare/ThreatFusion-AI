import { defineConfig } from '@playwright/test';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

// Fully isolated stack for browser tests:
//  - its own API on :8010 with a throwaway SQLite file, Neo4j disabled, demo mode on
//  - its own Vite dev server on :5175 proxying to that API
// It never touches the PostgreSQL/Neo4j containers or a running demo on :8000/:5173.
// The keys below are e2e-only test values for this ephemeral server, not secrets.
export const E2E_KEYS = {
  analyst: 'e2e-analyst-key-0123456789abcdef',
  approver: 'e2e-approver-key-0123456789abcdef',
};

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const python = process.env.TF_PYTHON ?? path.join(repoRoot, '.venv', 'bin', 'python');
const sqlitePath = path.join(os.tmpdir(), `threatfusion-e2e-${process.pid}.db`);

export default defineConfig({
  testDir: './e2e',
  timeout: 90_000,
  expect: { timeout: 15_000 },
  fullyParallel: false,
  workers: 1,
  retries: 0,
  reporter: [['list']],
  use: {
    baseURL: 'http://127.0.0.1:5175',
    channel: 'chrome', // uses the locally installed Google Chrome; no browser download
    headless: true,
    trace: 'retain-on-failure',
  },
  webServer: [
    {
      command: `"${python}" -m uvicorn api.app:app --host 127.0.0.1 --port 8010`,
      cwd: repoRoot,
      url: 'http://127.0.0.1:8010/health/live',
      reuseExistingServer: false,
      timeout: 60_000,
      env: {
        PERSISTENCE_BACKEND: 'sqlite',
        SQLITE_PATH: sqlitePath,
        NEO4J_ENABLED: 'false',
        WAZUH_ENABLED: 'false',
        DEMO_MODE: 'true',
        LLM_PROVIDER: 'none',
        MISP_API_KEY: 'REPLACE_WITH_MISP_API_KEY',
        API_KEYS: `e2e-analyst:analyst:${E2E_KEYS.analyst},e2e-approver:approver:${E2E_KEYS.approver}`,
        CORS_ORIGINS: 'http://127.0.0.1:5175',
      },
    },
    {
      command: 'npx vite --host 127.0.0.1 --port 5175 --strictPort',
      url: 'http://127.0.0.1:5175',
      reuseExistingServer: false,
      timeout: 60_000,
      env: { TF_API_URL: 'http://127.0.0.1:8010' },
    },
  ],
});
