import { defineConfig } from '@playwright/test'

const restoreDatabase = process.env.PROTOCOL_LAB_E2E_RESTORE_DATABASE_URL
const python = process.platform === 'win32' ? '../backend/.venv/Scripts/python.exe' : '../backend/.venv/bin/python'
export default defineConfig({
  testDir: './e2e', timeout: 120000,
  use: { baseURL: 'http://127.0.0.1:15173', browserName: 'chromium', actionTimeout: 15000, trace: 'retain-on-failure' },
  webServer: [
    {
      command: `${python} -m uvicorn protocol_lab.api.app:app --host 127.0.0.1 --port 18000 --app-dir ../backend/src`,
      env: { PROTOCOL_LAB_DATABASE_URL: process.env.PROTOCOL_LAB_E2E_DATABASE_URL ?? '', PROTOCOL_LAB_PROJECT_ROOT: process.env.PROTOCOL_LAB_E2E_ROOT ?? '../output/e2e-projects' },
      url: 'http://127.0.0.1:18000/api/v1/health', reuseExistingServer: false,
    },
    { command: 'npm run dev -- --port 15173', env: { PROTOCOL_LAB_API_URL: 'http://127.0.0.1:18000' }, url: 'http://127.0.0.1:15173', reuseExistingServer: false },
    ...(restoreDatabase ? [
      {
        command: `${python} -m uvicorn protocol_lab.api.app:app --host 127.0.0.1 --port 18001 --app-dir ../backend/src`,
        env: { PROTOCOL_LAB_DATABASE_URL: restoreDatabase, PROTOCOL_LAB_PROJECT_ROOT: process.env.PROTOCOL_LAB_E2E_RESTORE_ROOT! },
        url: 'http://127.0.0.1:18001/api/v1/health', reuseExistingServer: false,
      },
      { command: 'npm run dev -- --port 15174', env: { PROTOCOL_LAB_API_URL: 'http://127.0.0.1:18001' }, url: 'http://127.0.0.1:15174', reuseExistingServer: false },
    ] : []),
  ],
})
