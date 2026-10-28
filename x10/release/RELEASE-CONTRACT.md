# X10: контракт ограниченного Production V1

Статус: **определён кандидат профиля; Production V1 НЕ ПРИНЯТ**.
Профиль: `ubuntu-24.04-x86_64-node22-v1`, машинная декларация —
[profile.json](profile.json). Это G1: критерии записаны до измерений.
Наличие этого файла не закрывает G2–G8 и не означает публикацию пакета.

## Пользовательский результат

Доверенный оператор скачивает постоянный versioned пакет, устанавливает его
в новую личную папку без исходного checkout и компилятора, запускает обслуживаемый
native gateway и проксирует настоящее приложение. Он проверяет TLS, меняет
управляемую конфигурацию, получает явный отказ для неверного кандидата, возвращает
подтверждённую конфигурацию, перезапускает сервис, отдельно обновляет пакет и
возвращает предыдущий пакет. После остановки он может безопасно удалить только
принадлежащую ему подтверждённую установку.

Native NGINX обслуживает запросы. Node нужен для операторского CLI; он не становится
обязательным HTTP proxy в data path. Continuum не включается в production hot path.

## Один кандидат поддержанного профиля

| Область | Объявленный предел V1 | Что ещё требует доказательства |
| --- | --- | --- |
| Хост | Ubuntu 24.04, x86_64, Linux procfs, AF_UNIX, IPv4 loopback | Свежий совместимый nonroot host с существующим разрешённым user manager |
| Node | Major 22 | Точный patch, executable identity и запуск установленного CLI |
| Native ABI | PCRE2 headers10.42 / `libpcre2-8.so.0`; OpenSSL headers3.0.13 / `libssl.so.3`, `libcrypto.so.3`; zlib headers1.3 / `libz.so.1`; `libcrypt.so.1`; целевой glibc2.39 | Реальные package versions, runtime resolution, hashes всех зависимостей и отсутствие missing libraries |
| Установка | Новая canonical owned0700 private prefix, без symlink ancestors, high ports | Полный extracted-bundle путь без source checkout; unknown files и чужие PID должны отказать |
| Сервис | Целевой supervisor — `systemd --user`, явный private prefix/config | Recipe ещё не реализован/не принят; disconnect, restart, logging и crash recovery проверяются в G3–G5 |
| Gateway | HTTP/1.1 proxy, точная загрузка и streamed response; downstream HTTPS и verified HTTPS upstream | Реальные CA/hostname positive и negative controls на опубликованных bytes |
| Управление | Один same-UID оператор, private local/Unix control, явно managed fragment | Default admin exposure отсутствует; сокет/файлы/ошибки проверены независимо |

Это динамический bundle для конкретной принятой среды, не universal/static binary.
Совпадение SONAME или версии Ubuntu не доказывает переносимость. Итоговая поставка
записывает реальные версии, identities, build flags и actual build checkout.
Изменённые библиотеки требуют новой установки/приёмки, а не исправления hash record
старого пакета. Обновления безопасности не запрещаются: новый профиль/пакет должен
пройти свои проверки до продолжения поддержанной эксплуатации.

Текущая среда подготовки контракта имеет UID0 и Node24: clean nonroot/Node22 gate
в ней **не выполнен**. Исторический hosted Ubuntu24.04/Node22 compatibility PASS
не доказывает V1 service deployment. Контракт не разрешает sudo, изменение system
services, linger, production host, DNS или покупку новой инфраструктуры.
Если разрешённый совместимый user manager недоступен, service gate остаётся BLOCKED;
foreground alpha не переименовывается в обслуживаемый V1.

## Threat model и безопасные отказы

Оператор и другие процессы его UID доверены и не должны одновременно менять prefix
или гоняться с lifecycle. Hashes проверяют согласованность, не изолируют malicious
same-UID actor и не являются подписью. Существующий PID→signal race остаётся пределом;
проверка identity перед сигналом не называется OS-level fencing.

Prefix, TLS private keys, configs, state, journals и backups остаются приватными.
Публичная evidence содержит allowlisted counts/hashes/границы, не сырые configs,
logs, host paths, PID/namespace identities, session keys или credential URLs.
Сервис не открывает remote admin/RBAC endpoint. Публичный HTTP/TLS listener может
обслуживать приложение только в явно принятом оператором deployment; текущие
испытания используют loopback/high ports и собственные fixtures.

Symlinks, unknown files, чужой/непроверенный процесс, conflicting revision,
неизвестное durable state, pending transaction и ABI drift не получают зелёный
status. Для каждого поддержанного отказа нужен наблюдаемый результат и runbook.
Faulted master и возможные orphan workers запрещают автоматическое restart/uninstall
до проверки точных принадлежащих процессов. `killall`, перезапись неизвестных
файлов и рекурсивный repair не являются recovery.

## Health и два разных отката

Application readiness — отдельный idempotent endpoint настоящего приложения:
явные expected status/body, freshness и bounded response. Native demo self-check,
успешный `nginx -t`, generation metadata или завершённая status-команда не доказывают
здоровье приложения, listener drain или готовность всех workers.

Config apply/revert/recover действует на явно managed fragment и проверенные
journal/state boundaries. Кандидат уже может обслуживать запросы; отдельные samples
не дают all-traffic atomic cutover. Откат не отменяет уже совершённых запросов,
записей БД, платежей и иных application side effects.

Package upgrade/rollback — отдельный gate: новый private prefix side-by-side,
сохранённый known-good package/config/state, проверенная совместимость state и
резервная копия до переключения. Revert конфигурации не доказывает downgrade
бинарника. Нельзя молча переносить старый binding к новому master. Непроверенная
миграция, повреждённая история и неизвестное состояние требуют явного отказа.

## Критерии до замера

Точные числа и единицы находятся в `runtimeAcceptance` файла profile.json.
Это будущие pass/fail бюджеты первого bounded V1, не измеренная производительность,
не SLA и не основание обещать «10×».

- Выделенный разрешённый runtime host: 2vCPU, минимум4GiB RAM/2GiB свободного диска,
  2native workers; client/application/controller измеряются отдельно.
- После5минут warmup — не менее60минут soak:50минут normal и10минут normal+slow.
  Normal target100requests/s, максимум32concurrent, фактически не менее95requests/s.
  Во второй фазе дополнительно4slow connections:2upload и2download одновременно;
  размеры/rates/deadlines фиксированы в JSON. Отсутствующий throughput не считается выполненной нагрузкой.
- Для normal traffic: deadline2s, p99≤500ms,0unexpected HTTP/transport/TLS failures,
 0wrong payload/digest и0необъяснённой утраты application data. Отрицательные fault
  controls отдельно требуют конкретного ожидаемого отказа, не исключаются молча.
- Upload16MiB и stream8MiB должны иметь точные end-to-end bytes/digests.
  Плохой CA/hostname обязан отказать, хороший путь — реально обменяться payload.
- Суммарный RSS master+всех наблюдавшихся native workers≤256MiB; рост медианы
  последних5минут относительно первых5минут после warmup≤32MiB. Средний native CPU
  ≤1.5core при указанной нагрузке; sampling interval10s, пропуски явно UNKNOWN.
- Baseline/candidate native request path сравниваются на том же host с одинаковыми
  workers, applicable modules, TLS и application settings. Два baseline A/A окна
  по10минут предваряют сравнение; relative spread≤10%. Допустимый CPU mean ratio
  candidate/baseline≤1.25; near-zero baseline≤0.05core использует абсолютный
  дополнительный предел0.10core. Environment mismatch/необъяснённая variance —
  UNRESOLVED, не PASS и не маркетинговое ускорение.
- Startup/service restart/config operation — наблюдаемые бюджеты30s, package
  transition60s, cleanup принадлежащих fixtures30s. Graceful stop может сообщить
  оставшийся drain; это не успешное полное завершение. У неразрешённого cleanup
  результат FAIL. Kernel/filesystem stall не имеет обещанного hard deadline.

Каждый run закрепляет version/hash этого профиля, source/test/binary identities,
фактические host/dependency сведения и счётчики до замера. Изменение порога создаёт
новый candidate и новый run; прежний неблагоприятный результат сохраняется.
Порог нельзя снизить и переименовать уже полученный результат в PASS.

## Поставка и независимая приёмка

G2 Local Alpha — промежуточный постоянный versioned archive и проверенный extracted
operator path. Для G3–G8 дополнительно требуются service, реальный proxy/TLS,
config/package rollback/recovery, security/heldouts, frozen soak и повтор всего
пользовательского пути независимым оператором из опубликованных файлов.

Release record связывает source/tree/upstream, event head и actual build/PR merge
checkout, exact CI run/job/attempt/steps, native binary и generated inputs,
archive/payload identities, LICENSE/NOTICE/dependency inventory, поддержанный ABI,
постоянную release URL, operational/recovery evidence и reviewer. Истекающий CI
artifact не заменяет постоянную поставку. JSON Schema задаёт необходимую форму записи. Checker дополнительно сверяет
согласованность version/tag/canonical release URL, source/build/evidence refs и
последовательность gates. Одна схема не выполняет все эти проверки. Ни schema,
ни checker не загружают и не удостоверяют внешние доказательства: самозаявленный
`accepted` и ссылки без фактической проверки не принимают V1.

F5 CLA publisher failure сохраняется отдельно: никто не подписывает соглашение
за владельца и не скрывает этот failure для общего зелёного статуса.
Подпись продукта «Разработчик — АВЕРКРОН» не присваивает upstream NGINX/F5,
LICENSE/copyright/history сохраняются. Карточка продукта отражает реальную стадию.

## Сохранённая широкая программа

[PLAN](../PLAN.md), [ROADMAP](../ROADMAP.md) и [Continuum PLAN](../continuum/PLAN.md)
сохраняют web/reverse/load balancing/TCP/UDP/mail, HTTP2/3, QUIC, модули,
платформенные ветки, native/cloud/fleet management и незавершённый Continuum.
Компиляция105modules и отдельные fixtures не означают сертификацию всех сочетаний.

V1 явно не принимает полный semantic capsule, import, exclusive reader/writer,
distinct TLS code, old-code exit, native continuation, third-version adapters,
полное secret erasure или универсальное ускорение. Эти gates остаются открытыми.
После принятого G8 переход к AVERKRON выполняется только через G9/центральный CAS
с checkpoint/release/readback; этот контракт не активирует другой продукт.
