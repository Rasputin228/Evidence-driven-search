# Blue Static OSINT

Локальное OSINT-приложение на `FastAPI` с графовым UI и фоновыми задачами поиска.

Сборка и кастомизация: `Rasputin228`.

Тон проекта:

- low-energy shell;
- high-signal graph;
- холодный, ночной UI без тяжёлого визуального мусора.

## Что теперь интегрировано

- `Censys` для обогащения доменов и инфраструктурных следов через API.
  - `Censys Platform API v3` является основным режимом.
  - `Legacy Search API v2` оставлен как fallback.
- `Search4Faces` для поиска похожих профилей по загруженному изображению через API.
- `Maltego` через CSV-экспорт результатов для `Graph Import Wizard`.
- `SpiderFoot` как handoff в локальный Web UI, если у вас уже поднят свой инстанс.
- `Sherlock`, `Maigret`, `Holehe` остаются как опциональные внешние CLI-движки.

## Запуск

```powershell
./start.bat
```

или:

```powershell
./start.ps1
```

`start.ps1` теперь автоматически подхватывает переменные из локального файла `.env`, если он есть.

## Переменные окружения

- `OSINT_VERIFY_SSL=false`
- `OSINT_DB_PATH=./osint_graph_app.db`
- `CENSYS_PLATFORM_PAT=...`
- `CENSYS_API_ID=...`
- `CENSYS_API_SECRET=...`
- `SEARCH4FACES_API_KEY=...`
- `SPIDERFOOT_WEBUI_URL=http://127.0.0.1:5001`

Для быстрого старта можно скопировать `.env.example` в `.env` и заполнить нужные ключи.

Логика `Censys` такая:

- если задан `CENSYS_PLATFORM_PAT`, используется `Censys Platform API v3`;
- если `PAT` нет, но заданы `CENSYS_API_ID` и `CENSYS_API_SECRET`, используется `Legacy Search API`;
- если ключей нет, `Censys` тихо отключается без падения приложения.

`Search4Faces` и `SpiderFoot` также остаются optional-by-env.

## SQLite Persistence

Приложение больше не держит только in-memory состояние для ключевых backend-данных.

Теперь в `SQLite` сохраняются:

- кэш поисков;
- job runs;
- scan logs;
- результаты поисков;
- экспортированные `Maltego CSV`.

По умолчанию база создаётся в файле:

```text
./osint_graph_app.db
```

Это можно переопределить через `OSINT_DB_PATH`.

Минимальные таблицы:

- `search_runs`
- `search_results`
- `search_logs`
- `cache_entries`
- `exports`

Что это даёт:

- кэш и история переживают перезапуск процесса;
- `/api/search/jobs/{job_id}` читает состояние из `SQLite`;
- `/api/search/jobs?limit=20` отдаёт недавнюю историю запусков;
- экспорт в `Maltego` также сохраняется в локальной базе;
- незавершённые `queued/running` job-и после рестарта помечаются как прерванные.

## Healthcheck

`/api/health` теперь показывает:

- `censys_platform`
- `censys_legacy`
- `active_censys_mode`
- `sqlite_db_path`
- `cache_entries`
- `active_jobs`

## Экспорт в Maltego

После любого поиска по `username`, `email`, `phone` или `domain` можно:

- нажать кнопку `Экспорт в Maltego CSV` в UI;
- или вызвать endpoint вручную:

```text
/api/export/maltego?type=domain&target=example.com
```

CSV специально отдается в табличном виде для импорта через `Maltego Graph -> Import 3rd Party Table`.
