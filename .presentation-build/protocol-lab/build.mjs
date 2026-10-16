import fs from 'node:fs/promises';
import {Presentation, PresentationFile} from '@oai/artifact-tool';
import {finalizePresentation} from 'file:///C:/Users/rehy/.codex/plugins/cache/openai-primary-runtime/presentations/26.1013.11914/skills/presentations/container_tools/artifact_tool_utils.mjs';
const root='C:/Dev/Protocol-Lab', build=root+'/.presentation-build/protocol-lab';
const skill='C:/Users/rehy/.codex/plugins/cache/openai-primary-runtime/presentations/26.1013.11914/skills/presentations';
const p=Presentation.create({slideSize:{width:1280,height:720}});
const C={bg:'#071724',ink:'#EDF4F8',muted:'#B2C5D2',accent:'#53D7CB',amber:'#F7BD66'};
function text(s,t,x,y,w,h,size=28,color=C.ink,bold=false){const a=s.shapes.add({geometry:'textbox',position:{left:x,top:y,width:w,height:h},fill:'none',line:{fill:'none',width:0}});a.text=t;a.text.style={typeface:'Arial',fontSize:size,color,bold,insets:0,autoFit:'none',verticalAlignment:'top'};return a;}
function slide(title,section,notes){const s=p.slides.add();s.background.fill=C.bg;text(s,section,64,42,1100,26,18,C.accent,true);text(s,title,64,94,1152,100,44,C.ink,true);text(s,String(p.slides.items.length).padStart(2,'0'),1150,664,65,24,17,C.muted);s.speakerNotes.text=notes;return s;}
function item(s,head,body,y,x=64,w=700){text(s,head,x,y,w,38,29,C.ink,true);text(s,body,x,y+47,w,78,25,C.muted);}
function aside(s,top,body,foot){text(s,top,850,225,350,125,48,C.accent,true);text(s,body,850,370,350,150,27,C.ink);if(foot)text(s,foot,850,555,350,75,21,C.muted);}
let s=slide('','', 'Protocol Lab: локальная лаборатория исследования недокументированных бинарных TCP/IPv4-протоколов. Источники: README.md, AGENTS.md и требования R1–R6 из задания. Иллюстрация обложки: абстрактное изображение, созданное ImageGen, не схема реального протокола.');
const bytes=await fs.readFile(build+'/cover.png');s.images.add({blob:bytes.buffer.slice(bytes.byteOffset,bytes.byteOffset+bytes.byteLength),contentType:'image/png',position:{left:0,top:0,width:1280,height:720},fit:'cover'});
text(s,'Protocol Lab',64,190,780,100,80,C.ink,true);text(s,'Исследование бинарных\nTCP-протоколов',68,313,760,130,44,C.ink);text(s,'Проверяемые интерпретации\nна основе исходного сетевого обмена',68,514,650,86,28,C.muted);
s=slide('Метод исследования','ПОДХОД','Источники: docs/inference-a1.md, docs/inference-a4.md, docs/validation.md. Автоматический анализатор предлагает ограниченные кандидаты и сохраняет evidence. Discovery и holdout разделены. Поддержка детектора не означает универсальное распознавание протокола.');
item(s,'1. Наблюдение','Сравнение байтов и действий с разными параметрами.',219);
item(s,'2. Проверяемое правило','Явные границы, поля и условия применимости.',355);
item(s,'3. Проверка и уточнение','Контрпример ведёт к новой версии и повторному запуску.',491);
aside(s,'Поиск\nкандидатов','Повторы, энтропия, длины, счётчики и CRC помогают выбрать гипотезу.','Смысл поля остаётся предположением до независимой проверки.');
s=slide('Исходный обмен и точные источники','R1','Источники: docs/tcp-reconstruction.md, docs/acceptance.md (этапы 3–4). Сессия является экземпляром TCP-соединения. Одинаковые повторы не удваивают payload. Пропуски и конфликтующие перекрытия сохраняются явно, без заполнения нулями.');
item(s,'Импорт PCAP и PCAPNG','Оригинал, SHA-256, конкретное соединение и направление.',219);
item(s,'Восстановление TCP','Порядок sequence numbers, повторы, SYN/FIN и wrap.',355);
item(s,'Переход к источнику','Поле или диапазон потока связан с пакетами и их байтами.',491);
aside(s,'Пробелы\nвидны','Пропуски, усечение и конфликтующие байты имеют явную диагностику.','Границы TCP-сегментов не задают границы сообщений.');
s=slide('Сопоставление действий и байтов','R2','Источники: docs/investigation.md, docs/ui-workspace.md. Поиск HEX/ASCII, сравнение диапазонов, CSV/JSON журнал действий с поправкой часов, ручные связи. Временная близость сама по себе не доказывает связь. Наблюдения имеют стабильные source/stream anchors.');
item(s,'HEX / ASCII и поиск','Исходные байты доступны для непосредственной сверки.',219);
item(s,'Сравнение примеров','Различия и повторения при изменении параметра действия.',355);
item(s,'Журнал действий','CSV/JSON, поправка часов и связи с диапазонами обмена.',491);
aside(s,'Наблюдение','«При изменении параметра изменились эти байты».','Гипотеза о назначении поля хранит обоснование и ссылки на примеры.');
s=slide('Исполняемая модель протокола','R3','Источники: docs/framing.md, docs/interpretations.md, docs/inference-a4.md. JSON Schema/Pydantic валидируют декларативную модель; Construct исполняет поля. Модель не исполняет произвольный код. Изменения создают immutable версии.');
text(s,'Границы сообщений',64,220,540,45,32,C.accent,true);
text(s,'Ручные диапазоны\nФиксированный размер\nПоле длины\nНачальные и конечные маркеры',64,293,540,210,29);
text(s,'Поля и проверки',680,220,535,45,32,C.accent,true);
text(s,'Целые числа и порядок байтов\nДанные переменной длины\nМассивы и условные ветви\nКонстанты, диапазоны и checksum',680,293,535,210,29);
text(s,'Версионный JSON и общий движок применяют правила к новым записям.\nНеизвестные участки и семантические гипотезы остаются различимы.',64,565,1152,80,27,C.muted);
s=slide('Проверка корпуса и контрпримеры','R4','Источники: docs/validation.md, docs/portability.md, tests/fixtures/cli/length-model.json и expected.json. Иллюстрация основана на fixture length-big.pcap: правило constant n=3 даёт 1 passed и 2 failed, всего 15 bytes. Здесь не заявлен результат повторного запуска после правки. Технический лимит даёт unknown с диагностикой, а не опровержение протокольного правила.');
text(s,'Весь выбранный набор',64,218,710,45,32,C.accent,true);
text(s,'passed  /  failed  /  unknown\nambiguous  /  not_applicable',64,283,715,95,29);
text(s,'Видны фильтры, непокрытые байты и неполные данные.\nКаждый контрпример открывает исходный диапазон.',64,418,710,120,28);
text(s,'Новая версия модели делает старый запуск устаревшим.\nПовторная проверка показывает изменение результата.',64,558,710,80,25,C.muted);
aside(s,'1 passed\n2 failed','Тестовая модель требует n = 3. Другие длины выявляют слишком узкое правило.','Пример из тестового корпуса проекта.');
s=slide('Переносимое исследование','R5','Источники: docs/portability.md, docs/inference-a4.md. Bundle содержит consistent project-scoped PostgreSQL snapshot и content files. В актуальном расширении format 2 / metadata 0007, legacy format 1 поддержан. Restore требует локальную PostgreSQL и совместимые миграции. SHA-256 подтверждает целостность, не авторство.');
item(s,'Полный архив проекта','Оригиналы, модели, настройки, наблюдения и результаты.',219);
item(s,'История и доказательства','Версии, ссылки на источники и состояние актуальности.',355);
item(s,'Восстановление на другом месте','Относительные пути, manifest и проверка SHA-256.',491);
aside(s,'ZIP\n+ snapshot','Согласованный снимок данных PostgreSQL входит в архив.','На новой машине нужны локальная БД, зависимости и совместимые миграции.');
s=slide('Отчёт и применение к новой записи','R6','Источники: docs/portability.md, README.md, backend/src/protocol_lab/cli/main.py. Команда показана из корня репозитория, имена входов примерные. CLI apply не требует PostgreSQL, API или браузера. Exit 0 означает завершённую проверку, а не отсутствие failed/unknown. Для воспроизводимых примеров используются tests/fixtures/cli/length-model.json, tests/fixtures/framing/length-big.pcap и tests/fixtures/cli/expected.json.');
text(s,'Отчёт Markdown',64,220,540,45,32,C.accent,true);
text(s,'Основания выводов, примеры,\nконтрпримеры и открытые вопросы.\nЯвная область применимости.',64,290,540,140,28);
text(s,'Модель и результаты JSON',680,220,535,45,32,C.accent,true);
text(s,'Одна интерпретация для новых записей.\nGUI и CLI используют общий движок\nразбора и диагностики.',680,290,535,140,28);
text(s,'uv run --project backend --frozen protocol-lab apply\n  --model model.json --capture new.pcap --output result.json',64,485,1152,100,25,C.accent);
text(s,'В репозитории есть входные примеры и ожидаемые результаты.',64,605,1140,34,24,C.muted);
s=slide('Локальная архитектура','РЕАЛИЗАЦИЯ','Источники: docs/architecture.md, backend/pyproject.toml, frontend/package.json, README.md. API имеет один Uvicorn process, background tasks используют локальные worker processes. Offline режим доступен после установки зависимостей. PostgreSQL является runtime DB.');
const rows=[['Интерфейс','React / TypeScript, HEX, Monaco'],['API и фоновые задачи','FastAPI, локальные процессы, SSE и отмена'],['Общее ядро GUI / CLI','dpkt, TCP, framing, Construct, validation'],['Хранение','PostgreSQL и файлы под корнем проекта']];
rows.forEach((r,i)=>{text(s,r[0],64,220+i*91,410,48,28,C.accent,true);text(s,r[1],500,220+i*91,710,65,28,C.ink);});
text(s,'После установки зависимостей исследование работает без сети.\nИсходные записи остаются на локальной машине.',64,600,1140,65,25,C.muted);
s=slide('Демонстрация полного цикла','РЕЗУЛЬТАТ И ГРАНИЦЫ','Источники: пользовательские R1–R6, AGENTS.md, docs/acceptance.md, docs/reliability.md, docs/inference-a4.md. Это сценарий демонстрации, не утверждение о выполнении нового тестового прогона. Этап 10 ожидает ревью по документации. Native Linux SLA и суммарный RSS GUI/API/workers/DB не подтверждены. Автопоиск ограничен семействами правил и бюджетами.');
text(s,'01   Импорт записи и журнала действий\n02   Сравнение примеров и гипотеза\n03   Модель и проверка выбранного корпуса\n04   Контрпример, новая версия, повтор\n05   Перенос проекта и CLI на новой записи',64,225,750,290,30);
text(s,'Область работы',870,223,340,42,29,C.accent,true);
text(s,'Незашифрованные\nбинарные TCP/IPv4\nпротоколы.',870,282,340,125,28);
text(s,'IPv6, live capture,\nдешифрование и распаковка\nвне базового объёма.',870,455,340,120,24,C.muted);
text(s,'Технические лимиты указаны отдельно от свойств протокола.\nПолный native Linux профиль производительности ещё требует проверки.',64,580,750,76,24,C.amber);
await fs.writeFile(build+'/deck.json',JSON.stringify(p.toProto()));
for(let i=0;i<p.slides.items.length;i++){await fs.writeFile(build+`/slide-${i+1}.png`,new Uint8Array(await (await p.export({slide:p.slides.items[i],format:'png',scale:1})).arrayBuffer()));}
const candidate=build+'/candidate.pptx';await(await PresentationFile.exportPptx(p)).save(candidate);
const result=await finalizePresentation({workspaceDir:root,candidatePath:candidate,finalPath:root+'/output/presentations/Protocol-Lab-10-slides.pptx',pythonExecutable:'C:/Users/rehy/.cache/codex-runtimes/codex-primary-runtime/dependencies/python/python.exe',integrityValidatorPath:skill+'/container_tools/inspect_presentation_package_integrity.py',layoutValidatorPath:skill+'/container_tools/inspect_presentation_layout_geometry.py',layoutArgs:['--expected-slide-size-emu','12192000,6858000','--validate-bullet-geometry','--validate-heading-fit'],explicitTotalSlideCount:10,fontPolicy:{basis:'design',families:['Arial']},verifyArtifactToolImport:true,receiptPath:build+'/validation.json'});console.log(JSON.stringify(result));

