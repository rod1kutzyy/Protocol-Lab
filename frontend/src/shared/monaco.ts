import { loader } from '@monaco-editor/react'
import * as monaco from 'monaco-editor/esm/vs/editor/editor.api'
import 'monaco-editor/esm/vs/editor/edcore.main.js'
import 'monaco-editor/esm/vs/language/json/monaco.contribution'
import EditorWorker from 'monaco-editor/esm/vs/editor/editor.worker?worker'
import JsonWorker from 'monaco-editor/esm/vs/language/json/json.worker?worker'

self.MonacoEnvironment = {
  getWorker: (_id, label) => label === 'json' ? new JsonWorker() : new EditorWorker(),
}
// Use installed assets and bundled workers. No CDN requests at runtime.
loader.config({ monaco })
