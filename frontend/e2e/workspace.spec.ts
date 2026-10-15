import { expect, test, type Page } from '@playwright/test'

// UI-only regression suite: deterministic API responses, no research database.
const project = { id: 'project-ui', name: 'UI regression project' }
const capture = { id: 'capture-ui', project_id: project.id, sha256: 'a'.repeat(64), format: 'pcap', packet_count: 30, size_bytes: 8192, checksum_policy: 'warn', diagnostics: {} }
const streams = ['stream-a', 'stream-b'].map((id, index) => ({ id, session_id: 'session-ui', direction: index ? 'b_to_a' : 'a_to_b', reconstruction_version: 'tcp-v1', reconstruction_policy: 'explicit', extent: 8192, issues: [], spans: [] }))
const session = { id: 'session-ui', capture_id: capture.id, endpoint_a: { address: '192.0.2.10', port: 41000 }, endpoint_b: { address: '192.0.2.20', port: 9000 }, start_known: false, roles_known: false, diagnostics: ['Начало неизвестно'], packet_count: 30, section_index: 0, interface_id: 0, start_timestamp_ns: '1000000000', streams }
const spec = { schema_version: 'framing-1', start: 0, max_message_bytes: 65536, rule: { kind: 'fixed', size: 8 } }
const framing = { id: 'framing-ui', stream_id: streams[0].id, capture_id: capture.id, capture_sha256: capture.sha256, reconstruction_version: 'tcp-v1', engine_version: 'framing-v1', spec, extent: 8192, message_count: 1024, leftover_bytes: 0, uncertain_bytes: 0, pieces: [] }
const action = { id: 'action-ui', log_id: 'log-ui', row_index: 1, label: 'Set speed', timestamp_ns: '1000000000', parameters_json: '{"speed":2}' }
const anchor = { stream_id: streams[0].id, reconstruction_version: 'tcp-v1', byte_range: { start: 0, end: 4 } }
const hypothesis = { id: 'hypothesis-ui', hypothesis_id: 'hypothesis-root', statement: 'Маркер начала', rationale: 'Повторяется', scope: 'Корпус', unknowns: [], contradictions: [], observation_ids: [], created_at: '2026-10-15' }
const job = { id: 'verify-ui', kind: 'verify', status: 'succeeded', revision: 1, completed: 1, total: 1, message: 'Проверено', error: null, result: { outcome: 'verified' } }
const list = (items: unknown[] = []) => ({ items, next_offset: null })

async function fixture(page: Page) {
  const errors: string[] = [], unexpected: string[] = [], external: string[] = []
  page.on('pageerror', error => errors.push(error.message))
  page.on('request', request => { if (/^https?:/.test(request.url()) && !request.url().startsWith('http://127.0.0.1:')) external.push(request.url()) })
  await page.addInitScript(({ project, capture, session, streams }) => {
    localStorage.setItem('protocol-lab-selection', JSON.stringify({ version: 0, state: { projectId: project.id, captureId: capture.id, sessionId: session.id, streamId: streams[0].id, range: null, reference: null } }))
  }, { project, capture, session, streams })
  await page.route('**/api/v1/**', async route => {
    const url = new URL(route.request().url()), path = url.pathname.replace('/api/v1', '')
    const method = route.request().method()
    let body: unknown
    if (path === '/health') body = { version: 'ui-test', status: 'ok' }
    else if (path === '/projects') body = list([project])
    else if (path === `/projects/${project.id}`) body = project
    else if (path === `/projects/${project.id}/captures`) body = list([capture])
    else if (path === `/captures/${capture.id}`) body = capture
    else if (path === `/projects/${project.id}/sessions`) body = list([session])
    else if (path === `/sessions/${session.id}`) body = session
    else if (path === '/streams/stream-a' || path === '/streams/stream-b') body = streams.find(s => path.endsWith(s.id))
    else if (/^\/streams\/stream-[ab]\/bytes$/.test(path)) {
      const offset = Number(url.searchParams.get('offset')), length = Number(url.searchParams.get('length'))
      const stream = streams.find(s => path.includes(s.id))!
      body = { stream_id: stream.id, reconstruction_version: 'tcp-v1', offset, length, extent: stream.extent, blocks: [{ byte_range: { start: offset, end: offset + length }, status: 'known', variants: [{ data_hex: 'aa'.repeat(length), sources: [{ capture_id: capture.id, packet_id: 'packet-ui', packet_index: 14, packet_offset: 54, file_offset: 100, packet_payload_range: { start: offset, end: offset + length }, stream: { ...anchor, stream_id: stream.id, byte_range: { start: offset, end: offset + length } } }] }] }] }
    } else if (path === '/streams/stream-a/framing') body = list([framing])
    else if (path === '/streams/stream-b/framing') body = list()
    else if (path === '/framing-runs/framing-ui') body = framing
    else if (path === '/framing-runs/framing-ui/pieces' || path === '/framing-runs/framing-ui/interpretations') body = list()
    else if (path === `/projects/${project.id}/operations/verify`) body = job
    else if (path === '/jobs/verify-ui') body = job
    else if (path === '/jobs/verify-ui/events') return route.fulfill({ contentType: 'text/event-stream', body: `event: job\ndata: ${JSON.stringify(job)}\n\n` })
    else if (path === '/jobs') body = { items: [job] }
    else if (path === '/interpretations/schema') body = {}
    else if (path === `/projects/${project.id}/actions`) body = list([action])
    else if (path === `/projects/${project.id}/action-links`) body = list([{ id: 'link-ui', observation: { text: 'Связь действия', anchors: [anchor] } }])
    else if (path === `/projects/${project.id}/hypotheses`) body = list([hypothesis])
    else if (path === '/hypotheses/hypothesis-ui') body = hypothesis
    else if (path === '/hypotheses/hypothesis-ui/evidence') body = { items: [{ id: 'observation-ui', text: 'Повторяется AA', anchors: [anchor] }] }
    else if (new RegExp(`^/projects/${project.id}/(logs|action-logs|observations|interpretations|corpora|validation-runs)$`).test(path) && method === 'GET') body = list()
    else { unexpected.push(`${method} ${path}`); return route.fulfill({ status: 404, json: { detail: `Unexpected UI test request: ${path}` } }) }
    await route.fulfill({ status: method === 'POST' ? 202 : 200, json: body })
  })
  return { errors, unexpected, external }
}

async function section(page: Page, name: string) {
  await page.getByRole('navigation', { name: 'Разделы проекта', exact: true }).getByRole('link').filter({ hasText: name }).click()
  await expect(page.getByRole('heading', { name, exact: true }).first()).toBeVisible()
}

async function editorText(page: Page, value: string) {
  const editor = page.locator('.model-editor .monaco-editor')
  await expect(editor).toBeVisible()
  await editor.locator('.view-lines').click()
  await page.keyboard.press('ControlOrMeta+A')
  await page.keyboard.insertText(value)
}

test('sections preserve selection, drafts, editor, filters, scroll, actions and tasks', async ({ page }) => {
  await page.setViewportSize({ width: 1600, height: 1000 })
  const checks = await fixture(page)
  await page.goto('/#data')
  await page.getByLabel('IPv4 адрес', { exact: true }).fill('192.0.2.10')
  await page.getByRole('button', { name: 'Применить фильтры', exact: true }).click()
  await page.getByLabel('Файл записи', { exact: true }).setInputFiles({ name: 'draft.pcap', mimeType: 'application/octet-stream', buffer: Buffer.from('pcap') })
  await section(page, 'Исследование')
  await expect(page.getByRole('button', { name: 'Байт 0: AA', exact: true })).toBeVisible()
  await page.getByLabel('Начало диапазона', { exact: true }).fill('0')
  await page.getByLabel('Конец диапазона (не включён)', { exact: true }).fill('4')
  await page.getByRole('button', { name: 'Выделить диапазон', exact: true }).click()
  await page.getByRole('textbox', { name: 'Наблюдение', exact: true }).fill('Несохранённое наблюдение')
  await page.getByLabel('Поиск HEX-последовательности', { exact: true }).fill('AA 55')
  await page.getByRole('button', { name: 'Запомнить для сравнения', exact: true }).click()
  await page.getByRole('button', { name: 'Сравнить диапазоны', exact: true }).click()
  const hex = page.locator('.hex-scroll')
  await hex.evaluate(element => element.scrollTop = 560)
  await expect.poll(() => hex.evaluate(element => element.scrollTop)).toBe(560)
  // Let native scroll events reach the retained-screen scroll recorder.
  await section(page, 'Модель')
  await page.getByRole('combobox', { name: 'Сохранённый результат фрейминга', exact: true }).selectOption(framing.id)
  await page.getByRole('combobox', { name: 'Режим фрейминга', exact: true }).selectOption('fixed')
  await page.getByLabel('Фиксированный размер, bytes', { exact: true }).fill('12')
  await page.getByRole('button', { name: 'Поля и правила', exact: true }).click()
  const draft = '{"name":"НЕСОХРАНЁННЫЙ ЧЕРНОВИК","fields":[]}'
  await editorText(page, draft)
  await section(page, 'Проверка')
  await page.getByLabel('Название корпуса', { exact: true }).fill('Черновик корпуса')
  await section(page, 'Результаты')
  await section(page, 'Модель')
  await expect(page.locator('.model-editor')).toContainText('НЕСОХРАНЁННЫЙ ЧЕРНОВИК')
  await page.getByRole('button', { name: 'Границы сообщений', exact: true }).click()
  await expect(page.getByLabel('Фиксированный размер, bytes', { exact: true })).toHaveValue('12')
  await expect(page.getByRole('combobox', { name: 'Сохранённый результат фрейминга', exact: true })).toHaveValue(framing.id)
  await section(page, 'Исследование')
  await expect(page.getByRole('textbox', { name: 'Наблюдение', exact: true })).toHaveValue('Несохранённое наблюдение')
  await expect(page.getByLabel('Поиск HEX-последовательности', { exact: true })).toHaveValue('AA 55')
  await expect(page.locator('section[aria-label="Сравнение диапазонов"]')).toBeVisible()
  await expect.poll(() => hex.evaluate(element => element.scrollTop)).toBe(560)
  await page.getByRole('button', { name: 'Журнал действий', exact: true }).click()
  await page.getByRole('button', { name: 'Действие Set speed, строка 1' }).click()
  await page.getByLabel('Комментарий к ручной привязке', { exact: true }).fill('Черновик привязки')
  await page.getByRole('button', { name: 'Гипотезы', exact: true }).click()
  await page.getByRole('textbox', { name: 'Формулировка гипотезы', exact: true }).fill('Черновик гипотезы')
  await page.getByRole('button', { name: 'Задачи', exact: true }).click()
  await expect(page.getByRole('heading', { name: 'Фоновые задачи', exact: true })).toBeVisible()
  await page.getByRole('button', { name: 'Вернуться к проекту', exact: true }).click()
  await expect(page.getByRole('textbox', { name: 'Формулировка гипотезы', exact: true })).toHaveValue('Черновик гипотезы')
  await page.getByRole('button', { name: 'Журнал действий', exact: true }).click()
  await expect(page.getByLabel('Комментарий к ручной привязке', { exact: true })).toHaveValue('Черновик привязки')
  await page.getByRole('button', { name: 'Открыть связанные байты', exact: true }).click()
  await expect(page.getByRole('button', { name: 'Байты и источники', exact: true })).toHaveAttribute('aria-pressed', 'true')
  await expect(page.getByRole('textbox', { name: 'Наблюдение', exact: true })).toHaveValue('Несохранённое наблюдение')
  await expect(page.getByRole('button', { name: 'Байт 0: AA', exact: true })).toBeVisible()
  await section(page, 'Проверка')
  await expect(page.getByLabel('Название корпуса', { exact: true })).toHaveValue('Черновик корпуса')
  await section(page, 'Данные')
  await expect(page.getByLabel('IPv4 адрес', { exact: true })).toHaveValue('192.0.2.10')
  expect(await page.getByLabel('Файл записи', { exact: true }).evaluate((element: HTMLInputElement) => element.files?.[0]?.name)).toBe('draft.pcap')
  await page.goBack()
  await expect(page.getByRole('heading', { name: 'Проверка', exact: true })).toBeVisible()
  expect(checks).toEqual({ errors: [], unexpected: [], external: [] })
  await section(page, 'Исследование')
  await page.screenshot({ path: '../output/playwright/workspace-desktop.png' })
})

test('switching directions retains each stream draft and source navigation restores context', async ({ page }) => {
  const checks = await fixture(page)
  await page.goto('/#research')
  await page.getByLabel('Поиск HEX-последовательности', { exact: true }).fill('AA BB')
  await page.getByRole('button', { name: /^B → A/ }).click()
  await page.getByLabel('Поиск HEX-последовательности', { exact: true }).fill('CC DD')
  await page.getByRole('button', { name: /^A → B/ }).click()
  await expect(page.getByLabel('Поиск HEX-последовательности', { exact: true })).toHaveValue('AA BB')
  await page.getByRole('button', { name: 'Гипотезы', exact: true }).click()
  await page.getByRole('combobox', { name: 'Сохранённая версия гипотезы', exact: true }).selectOption(hypothesis.id)
  await page.getByRole('button', { name: /^К источнику/ }).click()
  await expect(page.getByLabel('Начало диапазона', { exact: true })).toHaveValue('0')
  await expect(page.getByLabel('Конец диапазона (не включён)', { exact: true })).toHaveValue('4')
  await expect(page.locator('.range-inspector')).toContainText('Пакет #14')
  expect(checks).toEqual({ errors: [], unexpected: [], external: [] })
})

for (const viewport of [{ width: 375, height: 812 }, { width: 812, height: 375 }]) {
  test(`navigation and controls fit ${viewport.width}×${viewport.height}`, async ({ page }) => {
    await page.setViewportSize(viewport)
    const checks = await fixture(page)
    await page.emulateMedia({ reducedMotion: 'reduce' })
    await page.goto('/#research')
    for (const name of ['Модель', 'Проверка', 'Результаты', 'Данные', 'Исследование']) await section(page, name)
    expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBe(true)
    await expect(page.getByRole('button', { name: 'Сменить соединение', exact: true })).toBeVisible()
    expect(checks).toEqual({ errors: [], unexpected: [], external: [] })
    await page.screenshot({ path: `../output/playwright/workspace-${viewport.width}.png` })
  })
}
