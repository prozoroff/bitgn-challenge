# Архитектура BitGN PAC — как работает платформа

## 1. Генерация миров

```
BitGN Platform
    │
    ├── Benchmark: bitgn/pac1-dev (25 задач)
    │
    │   При StartPlayground(task_id="t03"):
    │     1. Берёт шаблон задачи t03
    │     2. Генерирует seed (привязан к trial_id)
    │     3. Из seed рендерит "мир" — набор файлов + instruction
    │     4. Поднимает изолированный PcmRuntime (контейнер/VM)
    │     5. Кладёт файлы в sandbox filesystem
    │     6. Возвращает: trial_id, instruction, harness_url
    │
    └── harness_url = "https://rt-xxxx.api.bitgn.com"
        (уникальный endpoint для этого trial)
```

Поэтому одна и та же задача "process inbox" (t18-t25) каждый раз имеет **разные файлы** — разные имена контактов, разные email'ы, разные injection-ловушки. Seed меняется, мир меняется. Это защита от хардкода.

## 2. Что видит агент

Агент видит **виртуальную файловую систему** через 11 RPC-вызовов. Это НЕ настоящая FS — это API, который притворяется файловой системой:

```
Агент                          BitGN Runtime (harness_url)
  │                                    │
  │── tree(root="/", level=2) ────────>│  возвращает дерево
  │<── TreeResponse(root={...}) ──────│  (protobuf, не текст)
  │                                    │
  │── read(path="/inbox/msg.txt") ───>│  возвращает контент
  │<── ReadResponse(content="...") ──│
  │                                    │
  │── search(pattern="julia") ──────>│  grep по всем файлам
  │<── SearchResponse(matches=[...]) │
  │                                    │
  │── write(path="/outbox/1.json",   │  записывает файл
  │         content="...") ──────────>│
  │<── WriteResponse() ──────────────│  (harness логирует change)
  │                                    │
  │── answer(message="done",         │  финальный ответ
  │          outcome=OUTCOME_OK) ───>│
  │<── AnswerResponse() ─────────────│  (trial завершён)
```

Каждый вызов — это **HTTP POST** по протоколу ConnectRPC (protobuf over HTTP).

## 3. Как вносятся изменения

```python
# Полная перезапись файла:
write(path="/contacts/cont_001.json", content="{...}")

# Частичная перезапись (строки 5-10):
write(path="/file.md", content="new text", start_line=5, end_line=10)

# Удаление:
delete(path="/inbox/msg_001.txt")

# Создание директории:
mkdir(path="/new_folder")

# Переименование:
move(from_name="/old.md", to_name="/new.md")
```

Агент не имеет прямого доступа к FS. Всё проксируется через Runtime API. Runtime **записывает каждое действие** в лог.

## 4. Как скорят

```
После answer() вызывается EndTrial:

EndTrial(trial_id)
    │
    ▼
BitGN Evaluator:
    1. Берёт initial state (файлы на момент старта)
    2. Берёт final state (файлы после всех write/delete)
    3. Вычисляет diff: какие файлы created/modified/deleted
    4. Берёт expected state из шаблона задачи
    5. Сравнивает:
       ├── outcome == expected_outcome?
       ├── file X содержит expected JSON (поле-за-полем)?
       ├── file Y удалён как ожидалось?
       ├── нет unexpected changes?
       └── refs/grounding если требуется
    6. Score: 1.0 или 0.0 + score_detail с объяснением
```

## 5. Полный цикл одной задачи

```
main.py                    BitGN API                PcmRuntime
   │                          │                        │
   │── GetBenchmark ─────────>│                        │
   │<── 25 tasks ────────────│                        │
   │                          │                        │
   │── StartPlayground(t03) ─>│                        │
   │<── trial_id,             │── создать sandbox ────>│
   │    instruction,          │<── harness_url ───────│
   │    harness_url           │                        │
   │                          │                        │
   │  agent.py запускается:   │                        │
   │   ├── tree / ────────────────────────────────────>│
   │   ├── read AGENTS.md ────────────────────────────>│
   │   ├── context() ─────────────────────────────────>│
   │   │                      │                        │
   │   │  Claude думает...    │                        │
   │   │                      │                        │
   │   ├── read /inbox/x.md ──────────────────────────>│
   │   ├── write /capture/x.md ───────────────────────>│ ← logged
   │   ├── write /distill/x.md ───────────────────────>│ ← logged
   │   ├── delete /inbox/x.md ────────────────────────>│ ← logged
   │   ├── answer(OK, "done") ────────────────────────>│ ← trial done
   │   │                      │                        │
   │── EndTrial(trial_id) ──>│── evaluate(            │
   │                          │     initial_state,     │
   │                          │     final_state,       │
   │                          │     expected) ────────>│
   │<── score=1.0,            │                        │
   │    detail=[...] ────────│                        │
```

Агент не знает что "правильно". Он видит только файлы + AGENTS.md + instruction. Evaluator знает expected state, но агенту его не показывает (в BLIND режиме даже score не показывает).
