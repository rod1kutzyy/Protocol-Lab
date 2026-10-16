import { expect, test, type APIRequestContext } from '@playwright/test'
import { readFile } from 'node:fs/promises'
import path from 'node:path'

async function finish(api: APIRequestContext, id: string) {
  let result: { status: string; result?: Record<string, string>; error?: string } = { status: 'queued' }
  await expect.poll(async () => {
    result = await (await api.get(`/api/v1/jobs/${id}`)).json()
    return result.status
  }, { timeout: 60000 }).toBe('succeeded')
  return result.result!
}

for (const scenario of [
  { stage: 'A1', fixtures: ['length-discovery', 'length-holdout'], family: 'framing', kind: 'Поле длины', draftField: 'length_value' },
  { stage: 'A4', fixtures: ['crc-discovery', 'crc-holdout'], family: 'checksums', kind: 'Кандидат checksum/CRC', draftField: 'checksum' },
]) {
test(`${scenario.stage} search → evidence bytes → frozen holdout → model draft → reopen`, async ({ page, request }, testInfo) => {
  test.skip(!process.env.PROTOCOL_LAB_E2E_DATABASE_URL, 'Use the isolated PostgreSQL runner')
  const errors: string[] = [], external: string[] = []
  page.on('pageerror', e => errors.push(e.message))
  page.on('request', r => { if (/^https?:/.test(r.url()) && !r.url().startsWith('http://127.0.0.1:')) external.push(r.url()) })
  const project = await (await request.post('/api/v1/projects', { data: { name: 'A1 browser research' } })).json()
  const captures: string[] = []
  for (const name of scenario.fixtures) {
    const uploaded = await request.post(`/api/v1/projects/${project.id}/captures`, { multipart: { file: { name: `${name}.pcap`, mimeType: 'application/octet-stream', buffer: await readFile(path.resolve('..', 'tests/fixtures/inference', `${name}.pcap`)) }, checksum_policy: 'warn' } })
    expect(uploaded.status()).toBe(202)
    const capture = (await finish(request, (await uploaded.json()).id)).capture_id
    const reconstruct = await request.post(`/api/v1/captures/${capture}/reconstruct`, { data: {} })
    await finish(request, (await reconstruct.json()).id)
    captures.push(capture)
  }
  const corpus = await (await request.post(`/api/v1/projects/${project.id}/corpora`, { data: { name: 'A1 browser corpus', spec: { capture_ids: captures } } })).json()
  await page.goto('/')
  await page.getByRole('combobox', { name: 'Текущий проект', exact: true }).selectOption(project.id)
  await page.getByRole('link', { name: /^Исследование/ }).click()
  await page.getByRole('button', { name: 'Анализатор', exact: true }).click()
  const panel = page.locator('section[aria-label="Автоматический анализатор"]')
  await panel.getByRole('combobox', { name: 'Корпус анализатора', exact: true }).selectOption(corpus.id)
  await panel.getByRole('checkbox', { name: `Запись ${captures[1].slice(0, 8)}` }).check()
  await panel.getByText('Настройки, допущения и защитные пределы', { exact: true }).click()
  await panel.getByRole('button', { name: 'Открыть настройки JSON' }).click()
  const spec = JSON.parse(await panel.getByRole('textbox', { name: 'Спецификация анализатора', exact: true }).inputValue())
  spec.budget.max_header_bytes = 8
  spec.budget.max_rule_trials = scenario.stage === 'A4' ? 10000 : 5000
  if (scenario.stage === 'A4') spec.detectors = [{ family: 'framing' }, { family: 'checksums' }]
  spec.search.fixed_size_max = 64
  spec.search.adjustment_min = -8
  spec.search.adjustment_max = 8
  spec.search.marker_max_bytes = 4
  spec.search.max_marker_patterns = 8
  await panel.getByRole('textbox', { name: 'Спецификация анализатора', exact: true }).fill(JSON.stringify(spec))
  const searchResponse = page.waitForResponse(r => r.request().method() === 'POST' && r.url().endsWith(`/projects/${project.id}/inference-runs`))
  await panel.getByRole('button', { name: 'Найти кандидатов', exact: true }).click()
  const search = await searchResponse
  expect(search.status()).toBe(202)
  const searched = await finish(request, (await search.json()).id)
  await expect(panel.getByRole('list', { name: 'Кандидаты анализатора' }).getByRole('listitem').first()).toBeVisible()
  await panel.getByRole('combobox', { name: 'Семейство кандидатов', exact: true }).selectOption(scenario.family)
  await panel.getByRole('list', { name: 'Кандидаты анализатора' }).getByRole('listitem').filter({ hasText: scenario.kind }).first().click()
  await expect(panel.getByRole('heading', { name: scenario.kind, exact: true })).toBeVisible()
  await panel.getByRole('button', { name: 'Проверить на holdout', exact: true }).click()
  await expect(panel.getByRole('combobox', { name: 'Свидетельства', exact: true }).locator('option').filter({ hasText: 'holdout' })).toHaveCount(1)
  await expect(panel.getByText('Независимость: independent', { exact: false })).toBeVisible()
  await panel.getByRole('button', { name: 'Создать черновик модели', exact: true }).click()
  await expect(panel.getByRole('textbox', { name: 'Черновик исполняемой модели', exact: true })).toContainText(scenario.draftField)
  await panel.getByRole('button', { name: 'Сохранить черновик как новую модель', exact: true }).click()
  await expect(panel.getByText('Сохранена версия', { exact: false })).toBeVisible()
  await page.screenshot({ path: testInfo.outputPath(`inference-${scenario.stage}.png`), fullPage: true })
  await panel.getByRole('list', { name: 'Свидетельства кандидата' }).getByRole('listitem').first().click()
  await expect(page.locator('section[aria-label="Происхождение диапазона"]')).toBeVisible()
  await page.getByRole('button', { name: 'Анализатор', exact: true }).click()
  await expect(panel.getByRole('heading', { name: scenario.kind, exact: true })).toBeVisible()
  await page.reload()
  await page.getByRole('button', { name: 'Анализатор', exact: true }).click()
  await panel.getByRole('combobox', { name: 'Запуск анализатора', exact: true }).selectOption(searched.run_id)
  await expect(panel.getByRole('list', { name: 'Кандидаты анализатора' }).getByRole('listitem').first()).toBeVisible()
  expect(errors).toEqual([])
  expect(external).toEqual([])
})
}
