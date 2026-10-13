import { expect, test } from '@playwright/test'

test('localhost UI completes and cancels process jobs using SSE', async ({ page }) => {
  const external: string[] = []
  const errors: string[] = []
  page.on('pageerror', (error) => errors.push(error.message))
  page.on('request', (request) => { if (/^https?:/.test(request.url()) && !request.url().startsWith('http://127.0.0.1:')) external.push(request.url()) })
  await page.goto('/')
  await expect(page.getByText('API подключён', { exact: false })).toBeVisible()
  await page.getByRole('button', { name: 'Задачи', exact: true }).click()
  await page.getByRole('button', { name: 'Запустить диагностику' }).click()
  await expect(page.getByTestId('job-status')).toHaveText('Завершена', { timeout: 15000 })
  await page.getByText('JSON состояния задачи', { exact: true }).click()
  await expect(page.locator('.monaco-editor')).toBeVisible()
  await page.getByRole('button', { name: 'Запустить диагностику' }).click()
  await expect(page.getByTestId('job-status')).toHaveText('Выполняется')
  await page.getByRole('button', { name: 'Отменить', exact: true }).click()
  await expect(page.getByTestId('job-status')).toHaveText('Отменена')
  expect(external).toEqual([])
  expect(errors).toEqual([])
  await page.screenshot({ path: '../output/playwright/stage-2.png', fullPage: true })
})
