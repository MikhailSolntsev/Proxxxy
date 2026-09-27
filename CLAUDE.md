# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Что это

Однофайловая консольная утилита на .NET 10: локальный HTTP/HTTPS-прокси, который перенаправляет весь трафик через вышестоящий (upstream) прокси с Basic-аутентификацией. Весь код — в `Program.cs` (top-level statements), отдельных классов и DI-контейнера нет.

## Команды

```powershell
dotnet run                 # запустить прокси (займёт текущий терминал — цикл приёма соединений)
dotnet build               # сборка
dotnet build -c Release    # релизная сборка
```

Тестов в проекте нет. Проверка вручную:

```powershell
curl.exe -x http://127.0.0.1:18080 https://example.com/          # HTTPS через CONNECT-туннель
curl.exe -x http://127.0.0.1:18080 http://example.com/           # обычный HTTP
curl.exe -s -x http://127.0.0.1:18080 https://api.ipify.org/     # должен вернуть IP upstream-прокси
```

## Настройки

Читаются из `appsettings.json` рядом с исполняемым файлом (`CopyToOutputDirectory=PreserveNewest`, т.е. правится файл в корне проекта), десериализуются в класс `ProxyConfig`. Если рядом лежит `appsettings.local.json` (в `.gitignore`, не коммитится), из него читается только `UpstreamProxyUrl` и подставляется поверх значения из `appsettings.json` — так секрет не попадает в репозиторий, а в закоммиченном файле остаётся плейсхолдер `http://user:pass@host:port`. Ключи:

- `ListenHost` / `ListenPort` — локальный слушатель; по умолчанию `127.0.0.1:18080`.
- `UpstreamProxyUrl` — URL upstream-прокси вида `http://user:pass@host:port`. Схема `https` включает TLS до upstream-прокси, `http` — нет.
- `MaxHeaderBytes`, `HeaderTimeoutSeconds` — защита от соединений, которые открываются и молчат (иначе каждая такая попытка держит задачу и сокет навсегда).
- `AllowUntrustedUpstreamCertificate` — игнорировать ошибки сертификата upstream-прокси (по умолчанию `true`).
- `UpstreamSslProtocols` — версии TLS для соединения с https-upstream, например `"Tls12, Tls13"`; пустая строка = политика ОС.

Если `appsettings.json` не найден или в нём пустой `UpstreamProxyUrl`, программа печатает причину и завершается с кодом 1 — а не стартует молча с пустым upstream.

Учётные данные из `UserInfo` URL кодируются в Base64 и передаются как заголовок `Proxy-Authorization: Basic ...`.

**Важно про схему upstream-прокси.** Реальный upstream по адресу `168.80.203.17:8000` — обычный plaintext HTTP CONNECT-прокси: на TLS-handshake он не отвечает (соединение висит без ServerHello). Если в `UpstreamProxyUrl` указать `https://`, `AuthenticateAsClientAsync` уйдёт в бесконечное ожидание и все запросы будут виснуть — ровно этот симптом и был изначальной ошибкой. При смене upstream-прокси сначала проверьте, отвечает ли он по TLS:

```powershell
# если вернётся HTTP-статус — прокси plaintext, схема должна быть http://
curl.exe -v --max-time 10 -x http://<host>:<port> https://example.com/ --proxy-header "Proxy-Authorization: Basic <base64(user:pass)>"
```

## Архитектура

Поток обработки: `TcpListener` → на каждое входящее соединение `Task.Run(HandleClientAsync)` — поток на соединение, без ограничения параллелизма.

`HandleClientAsync` читает заголовки запроса (`ReadHeadersAsync`, посимвольное чтение до `\r\n\r\n`, с лимитом байт и таймаутом), затем открывает TCP-соединение с upstream (при необходимости оборачивая его в `SslStream`) и далее ветвится по методу:

- **CONNECT** — HTTPS-туннель: пересылает CONNECT upstream-прокси, проверяет ответ на 2xx (`IsSuccess`), отвечает клиенту `Connection Established` и дальше гоняет байты в обе стороны через два `CopyToAsync`, завершаясь по первому (`Task.WhenAny`). Полезная нагрузка не расшифровывается.
- **Остальные методы** — HTTP: пересылает строку запроса как есть (абсолютный URI сохраняется), вырезая только `strippedHeaders` (`Proxy-Authorization`, `Proxy-Connection`, `Connection` — свои подставляем сами), добавляет `Proxy-Authorization` и `Connection: close`. Остальные заголовки, включая `Transfer-Encoding`, сохраняются: тело идёт побайтово, поэтому chunked-разметка должна доехать до upstream вместе с телом.

Заголовки читаются и пишутся через `Encoding.Latin1` — побайтовое взаимно-однозначное кодирование, поэтому заголовки с не-ASCII байтами не искажаются. Не заменяйте на `Encoding.ASCII` или `UTF8`.

Особенности, о которых легко забыть при правках:

- Ошибки сертификата upstream-прокси игнорируются, если `AllowUntrustedUpstreamCertificate=true`.
- На каждый запрос — один обработчик: HTTP-ветка завершает соединение (`Connection: close`), переиспользование клиентского соединения не поддерживается.
- `Task.WhenAny` вместо `Task.WhenAll` намеренно: закрытие одной стороны туннеля завершает обработку, не дожидаясь второй.
- Исключения ловятся целиком в `HandleClientAsync` и только логируются — клиент в этом случае получает оборванное соединение. Отдельного логгера нет: `LogInfo`/`LogError` пишут в консоль на русском через общий `WriteLog`, который печатает время голубым, уровень (`info`/`error`) зелёным или красным, а сам текст — цветом консоли по умолчанию. Вывод обёрнут в `lock (consoleLock)`, чтобы при параллельных соединениях цвета одной записи не перемешивались с другой.

## CLAUDE.md

Файл написан вручную; при изменениях кода его нужно обновлять (особенно список настроек и предупреждение о схеме upstream).

## Безопасность

Репозиторий публичный. Рабочий upstream-URL с логином и паролем в открытом виде хранится только в `appsettings.local.json` (в `.gitignore`, не коммитится) — в закоммиченном `appsettings.json` держите плейсхолдер `http://user:pass@host:port`. При любых изменениях не тиражируйте реальные креды и не коммитьте их в новые файлы.

