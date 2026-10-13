import { expect, test, type Page } from '@playwright/test'
import { readFile, rename, mkdir } from 'node:fs/promises'
import path from 'node:path'
import { execFileSync } from 'node:child_process'

const root = path.resolve('..')
const fixture = (name: string) => path.join(root, 'tests/fixtures', name)

async function operation(page: Page, endpoint: string, action: () => Promise<unknown>) {
  const [response] = await Promise.all([
    page.waitForResponse(r => r.request().method() === 'POST' && r.url().endsWith(`/api/v1${endpoint}`)), action(),
  ])
  expect(response.status()).toBe(202)
  const job = await response.json()
  let state = job
  await expect.poll(async () => {
    state = await (await page.request.get(`${new URL(page.url()).origin}/api/v1/jobs/${job.id}`)).json()
    return state.status
  }, { timeout: 60000 }).toBe('succeeded')
  return state.result
}

async function editModel(page: Page, document: object) {
  const editor = page.locator('.model-editor .monaco-editor')
  await expect(editor).toBeVisible()
  await editor.locator('.view-lines').click()
  await page.keyboard.press('ControlOrMeta+A')
  await page.keyboard.press('Backspace')
  await page.keyboard.insertText(JSON.stringify(document))
  const [checked] = await Promise.all([
    page.waitForResponse(r => r.request().method() === 'POST' && r.url().endsWith('/interpretations/check')),
    page.getByRole('button', { name: 'Проверить модель', exact: true }).click(),
  ])
  expect(await checked.json()).toMatchObject({ valid: true })
  const [response] = await Promise.all([
    page.waitForResponse(r => r.request().method() === 'POST' && /\/projects\/[^/]+\/interpretations$/.test(r.url())),
    page.getByRole('button', { name: 'Сохранить новую версию', exact: true }).click(),
  ])
  expect(response.status()).toBe(201)
  return response.json()
}

async function download(page: Page, name: string | RegExp, target: string) {
  const [file] = await Promise.all([page.waitForEvent('download'), page.getByRole('link', { name }).click()])
  await file.saveAs(target)
}

test('research → counterexample → revision → portable restore → new-capture CLI', async ({ page }, testInfo) => {
  test.skip(!process.env.PROTOCOL_LAB_E2E_DATABASE_URL || !process.env.PROTOCOL_LAB_E2E_RESTORE_DATABASE_URL,
    'Run scripts/run_e2e.py with a local test DB; never use the research database')
  const external: string[] = [], errors: string[] = []
  page.on('pageerror', e => errors.push(e.message))
  page.on('request', r => { if (/^https?:/.test(r.url()) && !/^http:\/\/127\.0\.0\.1:/.test(r.url())) external.push(r.url()) })
  await page.goto('/')
  await page.getByLabel('Название проекта', { exact: true }).fill('Stage 10 research')
  const [created] = await Promise.all([
    page.waitForResponse(r => r.request().method() === 'POST' && r.url().endsWith('/api/v1/projects')),
    page.getByRole('button', { name: 'Создать проект' }).click(),
  ])
  const project = (await created.json()).id
  const imports = page.locator('section[aria-label="Импорт записи"]')
  await page.getByLabel('Файл записи', { exact: true }).setInputFiles(fixture('framing/length-big.pcap'))
  const original = await operation(page, `/projects/${project}/captures`, () => imports.getByRole('button', { name: 'Импортировать запись' }).click())
  await expect(imports.getByRole('button', { name: 'Восстановить TCP' })).toBeEnabled()
  await operation(page, `/captures/${original.capture_id}/reconstruct`, () => imports.getByRole('button', { name: 'Восстановить TCP' }).click())
  await page.getByRole('list', { name: 'TCP-сессии' }).getByRole('listitem').first().click()
  await expect(page.getByRole('button', { name: 'Байт 0: 00', exact: true })).toBeVisible()
  await page.getByLabel('Начало диапазона', { exact: true }).fill('0')
  await page.getByLabel('Конец диапазона (не включён)', { exact: true }).fill('2')
  await page.getByRole('button', { name: 'Выделить диапазон', exact: true }).click()
  const sources = page.locator('section[aria-label="Происхождение диапазона"]')
  await sources.getByRole('button', { name: /^Пакет #/ }).first().click()
  await expect(sources.getByText('seq=100', { exact: false })).toBeVisible()
  await page.getByLabel('Наблюдение', { exact: true }).fill('First two bytes vary with payload length')
  await page.getByRole('button', { name: 'Сохранить наблюдение' }).click()
  await expect(sources.locator('.observation').filter({ hasText: 'First two bytes' })).toBeVisible()

  await page.getByLabel('Файл журнала', { exact: true }).setInputFiles(fixture('actions/clock-offset.csv'))
  await page.getByRole('button', { name: 'Посмотреть поля' }).click()
  await page.getByRole('combobox', { name: 'Поле времени', exact: true }).selectOption('when')
  await page.getByRole('combobox', { name: 'Поле действия', exact: true }).selectOption('operation')
  await page.getByRole('combobox', { name: 'Поле параметров', exact: true }).selectOption('args')
  await page.getByRole('combobox', { name: 'Формат времени', exact: true }).selectOption('unix_s')
  await operation(page, `/projects/${project}/action-logs`, () => page.getByRole('button', { name: 'Импортировать журнал' }).click())
  await expect(page.getByRole('button', { name: 'Действие Set speed, строка 1' })).toBeVisible()
  await page.getByRole('button', { name: 'Действие Set speed, строка 1' }).click()
  await expect(page.getByRole('heading', { name: 'Выбрано действие: Set speed' })).toBeVisible()
  await page.getByRole('button', { name: 'Действие Set speed, строка 2' }).click()
  await page.getByLabel('Комментарий к ручной привязке', { exact: true }).fill('Action with parameter 2')
  await page.getByRole('button', { name: 'Привязать действие к выделению' }).click()
  await expect(page.getByRole('button', { name: 'Открыть связанные байты' })).toBeVisible()

  const framing = page.locator('section[aria-label="Фрейминг потока"]')
  await page.getByRole('combobox', { name: 'Режим фрейминга', exact: true }).selectOption('length')
  await page.getByRole('combobox', { name: 'Ширина поля, bytes', exact: true }).selectOption('2')
  await page.getByLabel('Поправка длины', { exact: true }).fill('2')
  const stream = (await (await page.request.get(`/api/v1/captures/${original.capture_id}/sessions`)).json()).items[0].streams[0].id
  await operation(page, `/streams/${stream}/framing`, () => framing.getByRole('button', { name: 'Построить предварительный просмотр' }).click())
  await expect(framing.getByText('Сообщений: 3.', { exact: false })).toBeVisible()
  const document = JSON.parse(await readFile(fixture('cli/length-model.json'), 'utf8'))
  const firstModel = await editModel(page, document)

  await page.getByRole('button', { name: 'Гипотезы и проверка корпуса', exact: true }).click()
  await page.getByLabel('Формулировка гипотезы', { exact: true }).fill('Header may encode payload length')
  await page.getByLabel('Основания и рассуждение', { exact: true }).fill('Different lengths occur in the same connection')
  await page.getByLabel('Область применимости', { exact: true }).fill('Synthetic selected captures')
  await page.getByRole('list', { name: 'Выбор наблюдений' }).getByRole('listitem').filter({ hasText: 'First two bytes' }).click()
  await page.getByRole('button', { name: 'Сохранить гипотезу', exact: true }).click()
  await expect(page.locator('.hypothesis-card')).toContainText('Header may encode payload length')
  await page.getByLabel('Название корпуса', { exact: true }).fill('Research corpus')
  await page.getByRole('button', { name: 'Выбрать загруженные записи' }).click()
  await page.getByRole('button', { name: 'Сохранить версию корпуса', exact: true }).click()
  await page.getByRole('combobox', { name: 'Модель для корпуса', exact: true }).selectOption(firstModel.id)
  const corpusPanel = page.locator('section[aria-label="Проверка корпуса"]')
  await expect(corpusPanel.getByRole('button', { name: 'Проверить весь корпус' })).toBeEnabled()
  const first = await operation(page, `/projects/${project}/validation-runs`, () => corpusPanel.getByRole('button', { name: 'Проверить весь корпус' }).click())
  await expect(corpusPanel.getByRole('table', { name: 'Полное покрытие выбранных записей' })).toBeVisible()
  await expect(corpusPanel.getByRole('row').filter({ hasText: 'Failed ·' }).getByRole('cell').nth(1)).toHaveText('2')
  await page.getByRole('combobox', { name: 'Фильтр списка результатов', exact: true }).selectOption('failed')
  await page.getByRole('list', { name: 'Результаты корпуса' }).getByRole('listitem').first().click()
  await expect(page.getByRole('list', { name: 'Поля контрпримера' }).getByRole('listitem').first()).toContainText('n = 5')
  await page.getByRole('button', { name: 'Открыть диапазон → bytes и пакеты' }).click()
  await expect(page.getByText('Выделено [5, 12)', { exact: false })).toBeVisible()
  // Navigation loads the saved framing/model; choose it explicitly before editing.
  await page.getByRole('combobox', { name: 'Сохранённый результат фрейминга', exact: true }).selectOption({ index: 1 })
  await page.getByRole('combobox', { name: 'Версия модели', exact: true }).selectOption(firstModel.id)
  delete document.fields[0].constant
  const revised = await editModel(page, document)
  await page.getByRole('button', { name: 'Гипотезы и проверка корпуса', exact: true }).click()
  await page.getByRole('button', { name: 'Проверить актуальность', exact: true }).click()
  await expect(corpusPanel.getByText('Устаревший результат:', { exact: false })).toBeVisible()
  await page.getByRole('combobox', { name: 'Модель для корпуса', exact: true }).selectOption(revised.id)
  const second = await operation(page, `/projects/${project}/validation-runs`, () => corpusPanel.getByRole('button', { name: 'Проверить весь корпус' }).click())
  await expect(corpusPanel.getByRole('row').filter({ hasText: 'Passed ·' }).getByRole('cell').nth(1)).toHaveText('3')
  await page.getByRole('combobox', { name: 'Сравнить текущий запуск с', exact: true }).selectOption(first.run_id)
  await expect(page.getByText('Изменился статус: 2', { exact: false })).toBeVisible()

  await page.reload()
  await page.getByRole('button', { name: 'Исходные данные', exact: true }).click()
  await page.getByRole('button', { name: 'Открыть связанные байты' }).click()
  await expect(page.getByText('Выделено [0, 2)', { exact: false })).toBeVisible()
  await page.getByRole('button', { name: 'Перенос и отчёт', exact: true }).click()
  const portable = page.locator('section[aria-label="Сохранение и экспорт проекта"]')
  await expect(portable.getByRole('button', { name: 'Экспортировать проект ZIP' })).toBeEnabled()
  await operation(page, `/projects/${project}/operations/export`, () => portable.getByRole('button', { name: 'Экспортировать проект ZIP' }).click())
  const output = testInfo.outputPath('artifacts')
  await mkdir(output, { recursive: true })
  const archive = path.join(output, 'project.zip'), modelPath = path.join(output, 'model.json')
  await download(page, /^Скачать .*\.zip$/, archive)
  await page.getByRole('combobox', { name: 'Версия интерпретации для JSON', exact: true }).selectOption(revised.id)
  await download(page, 'Скачать интерпретацию JSON', modelPath)
  await operation(page, `/projects/${project}/operations/report`, () => portable.getByRole('button', { name: 'Сформировать Markdown-отчёт' }).click())
  const report = path.join(output, 'report.md')
  await download(page, /^Скачать .*\.md$/, report)
  expect(await readFile(report, 'utf8')).toContain('Header may encode payload length')
  await page.screenshot({ path: path.join(output, 'export.png'), fullPage: true })

  await page.goto('http://127.0.0.1:15174')
  const sourceRoot = process.env.PROTOCOL_LAB_E2E_ROOT!
  await rename(sourceRoot, `${sourceRoot}-unavailable`)
  await page.getByLabel('Архив проекта ZIP', { exact: true }).setInputFiles(archive)
  await operation(page, '/projects/restore', () => page.getByRole('button', { name: 'Восстановить проект', exact: true }).click())
  await expect(page.getByRole('heading', { name: 'Stage 10 research', exact: true })).toBeVisible()
  await page.getByRole('button', { name: 'Открыть связанные байты' }).click()
  await expect(page.getByRole('button', { name: 'Байт 0: 00', exact: true })).toBeVisible()
  await expect(page.getByText('Выделено [0, 2)', { exact: false })).toBeVisible()
  await page.locator('section[aria-label="Происхождение диапазона"]').getByRole('button', { name: /^Пакет #/ }).first().click()
  await expect(page.getByText('seq=100', { exact: false })).toBeVisible()
  const restored = await (await page.request.get(`${new URL(page.url()).origin}/api/v1/validation-runs/${second.run_id}`)).json()
  expect(restored.coverage.message_counts.passed).toBe(3)
  const applied = path.join(output, 'new-capture.json')
  execFileSync(path.join(root, 'backend/.venv/bin/protocol-lab'), ['apply', '--model', modelPath,
    '--capture', fixture('interpretation/arrays-new-parameters.pcap'), '--output', applied],
    { env: { ...process.env, PROTOCOL_LAB_DATABASE_URL: '' } })
  expect(JSON.parse(await readFile(applied, 'utf8')).run.coverage.message_counts.passed).toBe(1)
  expect(external).toEqual([])
  expect(errors).toEqual([])
  await page.screenshot({ path: path.join(output, 'restored.png'), fullPage: true })
})
