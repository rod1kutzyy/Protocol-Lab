import Editor from '@monaco-editor/react'
import './monaco'
export default function JsonPreview({ value }: { value: string }) {
  return <Editor height="260px" language="json" value={value} options={{ readOnly: true, minimap: { enabled: false }, automaticLayout: true, scrollBeyondLastLine: false }} loading={<p>Загрузка локального редактора…</p>} />
}
