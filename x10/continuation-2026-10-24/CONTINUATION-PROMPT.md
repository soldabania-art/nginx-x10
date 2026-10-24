# X10 — подробный промпт продолжения до промышленного V1

> Единый допуск диспетчера: реализация начинается только при свежих `execution.phase=RUNNING`, `execution.transition=null`, `execution.activeProject=x10` и `status=ACTIVE_FOR_V1` этого проекта. Исторический ACTIVE или WAITING не заменяет текущий допуск. При TRANSITIONING новый writer не стартует; прежний завершает checkpoint/release/readback, затем координатор одним CAS активирует следующий проект.

Версия документа: 24 октября 2026 года. Язык работы и отчётов владельцу — русский.
Это самостоятельное задание для нового координатора и его временных помощников.
Прочитай документ полностью до изменений. Исторический SHA здесь — датированный
снимок, а не разрешение продолжать из устаревшей папки.

## 1. Поручение владельца и очередь портфеля

Ты отвечаешь за доведение X10 до работающего, проверенного и поставляемого V1.
Первая Linux alpha — промежуточная поставка, а не завершение всего X10.
Порядок владельца: X10 → новый AVERKRON → TEXTORA / AI Index → TROVENDI →
Replyscope. Остальные продукты должны впоследствии заработать; их задачи не
теряются, но основная команда не распыляется на одновременные запуски.

Новый AVERKRON — главный сайт всей площадки. Собственные продукты представлены
на его /cases/ («Наши проекты») с подписью «Разработчик — АВЕРКРОН». Названия
продуктов сохраняются. Для X10 обязательно сохраняются исходные авторство,
copyright, LICENSE и история NGINX; подпись AVERKRON относится к собственной
разработке продукта, а не к присвоению upstream NGINX или одобрению со стороны F5.

Центральное управление портфелем ведётся в приватном soldabania-art/engine-x10:
- docs/PORTFOLIO-EXECUTION.md — действующее поручение и порядок;
- docs/PORTFOLIO-STATE.json — активный продукт, точные ref и состояния ворот;
- закреплённый в этом манифесте X10 CONTINUATION-PROMPT.md и GATES.json.

В текущем поручении X10 имеет состояние ACTIVE_FOR_V1. Не подменяй его статусом
«готово» после alpha, зелёного CI или одного пакета. При первой загрузке получи
свежий main центрального repo и зафиксируй SHA прочитанных документов.
Доступные owner-агенты читают приватный координатор разрешёнными средствами.
Его точные private commit SHA, внутренние бюджеты и ценовые предположения не
переносятся в публичные копии этих документов. Публичные технические X10 SHA,
CI run/job и очищенное evidence сохраняются для воспроизводимости.

Пути выше могут появиться в отдельном коммите публикации root: отсутствие файла
не разрешает выдумать его содержание или вернуться к старому приоритету.
Координатор сообщает конкретный рассинхрон и использует последнее прямое поручение
владельца в пределах уже разрешённой работы.

## 2. Как понимать цель, не урезая утверждённый scope

Долгосрочный X10 остаётся самостоятельным native продуктом на основе полного
NGINX Open Source: веб-сервер, reverse proxy, балансировщик, TCP/UDP/mail proxy,
совместимость конфигураций и модулей, полезное управление и проверяемые улучшения.
Полная матрица x10/PLAN.md сохраняется. Нельзя удалять её строки, протоколы,
модули или platform branches ради объявления завершения.

Готовность разделяется на четыре уровня:
1. Engineering snapshot: код/fixtures, локальные проверки, необязательно поставка.
2. Local Alpha: изолированный loopback Linux install/run/apply/revert/recover/
   stop/uninstall с реальным пакетом и честными ограничениями.
3. Production V1: законченный self-hosted native gateway и операторский путь для
   одного явно поддержанного Linux-профиля, работающий вне development checkout.
   Имеет воспроизводимый выпуск, эксплуатацию, обновление/возврат и приёмку ниже.
4. Расширенная платформа / Continuum: дальнейшие профили, fleet/cloud/console,
   широкая совместимость и измеренные оптимизации, semantic TLS migration.

Рекомендуемый конечный порог для передачи основной команды AVERKRON — уровень 3.
Это явная граница первого V1, не заявление, что завершены все будущие улучшения,
доказано универсальное 10× или закрыт весь Continuum. Зафиксируй принятую границу
в центральном манифесте и release contract до разработки. Сохрани отложенную
матрицу и её критерии; не переименовывай незавершённую исследовательскую цель
в готовую возможность. Не создавай новый конструктор сайтов вместо этого выпуска.

## 3. Датированный исходный снимок

Подробное состояние и доказательства находятся в CURRENT-STATE.md и
CI-EVIDENCE-SNAPSHOT.json рядом с этим промптом.

Прочитано 24.10.2026 около 10:37–10:45 UTC:
- native repo: soldabania-art/nginx-x10;
- active branch: x10-continuum-development;
- датированный HEAD: bf7f9aa23f3fb714ee31fa044853c3c48fff4eb4;
- upstream master: 148c75678cd4171338c31d4ed4c02411736d5fe9;
- прежняя integration base x10-main: 0b622c4a9f4dfe0876209c2a8bf5ce5e25caa812;
- прежняя x10-development сохранена как история;
- приватный координатор engine-x10: читать свежий доступный owner-агенту main;
  точный SHA приватного repo в публичном handoff не публиковать.

Два repo X10 — один продукт, но разные реализации. engine-x10 содержит более
ранний Node gateway и консоль; он не является native data plane и не получает
параллельную разработку второй замены NGINX. Не используй его Vercel READY как
доказательство установки или работоспособности native gateway.

На снимке GitHub Releases native repo пусты. Draft PR #2 не merged.
Quickstart всё ещё клонирует прежнюю x10-development: это известный docs defect,
а не канонический release ref. Перед выпуском исправь инструкцию на конкретный
принятый ref. Архив из GitHub Actions истекает и не заменяет постоянную поставку.

Контрольное чтение в10:49UTC обнаружило более поздний HEAD
66a65419a04ec5e4ff3604dec214d553a85f2a1b и implementation
c0c4e308eca839049de4b64aa2fd2493d0b8865c (API metadata; локальный C2a48).
Новый чужой lease CI-review действует до11:32:42UTC /15:32:42Самара.
Exact новые PR runtime jobs тогда ещё выполнялись. CURRENT-STATE.md содержит
эту поправку; counts44 и artifact ниже сохраняются как проверенный прошлый
снимок. Новый48-case local checkpoint не принят этим документом как hosted PASS.

## 4. Источники истины и обязательное чтение

Приоритет: новое прямое поручение владельца → свежий центральный execution
manifest → AGENTS нужного repo → точный текущий checkpoint и применимый lease →
принятый release contract → планы → исторические отчёты.

Из одного зафиксированного remote SHA прочитай:
- AGENTS.md;
- x10/README.md, PLAN.md, STATUS.md, ROADMAP.md;
- x10/BUILD.md, CI.md, QUICKSTART.md;
- x10/alpha/README.md, x10/control/README.md;
- x10/continuum/README.md, PLAN.md, OPERATIONS.md, BACKGROUND.json;
- текущие evidence/per-file ledger и pendingVerification из BACKGROUND;
- изменяемые source/tests и относящиеся к ним native lifetime/event/buffer contracts;
- .github/workflows/x10-native.yml, x10-continuum.yml и scope classifier;
- x10/upstream.json, LICENSE и используемый official test pin;
- для коммерческой работы: continuum/COMMERCIAL.md и ECONOMICS.md.

В снимке отдельного файла Continuum MASTER нет: master-план образуют перечисленные
PLAN/README/OPERATIONS. Не создавай его замену и не выводи план из названия ветки.
Ссылки и ключевые исторические ограничения проверяй по реальным файлам.

Статусы в начале длинного STATUS/ROADMAP могут быть историческими. Последнее
утверждение pending сверяй с exact implementation SHA, текущими CI jobs и receipts.
Новый успех нельзя приписывать изменённому коду только по старой квитанции.

## 5. Bootstrap каждого прохода

1. Получи свежие central main, native active HEAD, integration/release refs и PR.
2. Прочитай BACKGROUND именно из найденного native HEAD; запиши время UTC.
3. Проверь действующий чужой lease, статус текущего product stage и ownership.
4. Определи опубликованный accepted SHA, последний implementation SHA, CI SHA,
   реальный PR merge checkout, pending задачи и изменения после прошлого среза.
5. Получи отдельный чистый checkout/worktree. Не используй папку другого агента,
   старый scratch, чужие build products или неподтверждённый бинарник.
6. Проверь доступные Node/компилятор/Python/Perl/Git/Unix sockets/права. Результат
   capability check — наблюдение, а не повод ослабить обязательный gate.
7. Выбери один следующий ограниченный пакет из GATES.json и центрального манифеста.
8. Перед назначением writers получи и перечитай собственное владение.
9. Зафиксируй вход, ожидаемый пользовательский результат, пределы, зависимости,
   файлы, команды и доказательство завершения. Только затем работай.

Шаблон команд для собственного checkout (значения назначает координатор):
```sh
git clone --branch x10-continuum-development https://github.com/soldabania-art/nginx-x10.git nginx-x10-work
cd nginx-x10-work
git checkout --detach FULL_SHA_READ_FROM_REMOTE
git status --short
node --version
python3 --version
cc --version
```
FULL_SHA_READ_FROM_REMOTE — обязательная подстановка проверенного SHA, не
буквальная команда и не постоянный SHA данного исторического снимка.
При недоступном clone используй доступный GitHub connector/CI для допустимых
чтений и проверок; отсутствие исполнения обозначь как конкретный блокер.
Не объявляй локальную сборку выполненной по содержимому README.

## 6. Координация: чужой lease, CAS, ветки и публикация

На снимке был живой чужой lease:
- runId continuum-api-20261024T101550264Z;
- owner codex-coordinator-api-inventory;
- срок до 2026-10-24T11:00:50.264Z / 15:00:50.264 Самара;
- baseCommit ad5351f475c4dc35d292cfd1ec3384cbc9579e3b;
- задача — exact protection CI и bounded read-only API inventory, без importer.

Это историческая запись, не утверждение, что lease жив сейчас. Проверь свежий.
При живом чужом lease не меняй active ref, BACKGROUND, AGENTS и его
файлы; не перезапускай и не прерывай чужой проход через расписание; даже непересекающийся docs commit меняет ancestry и нарушает publication
fence. Допустимы чтение и отдельное локальное предложение. Root может хранить
промпт на отдельной docs-ветке/PR и закрепить его ref в центральном манифесте.
PR не становится принятым изменением автоматически; merge/auto-merge не включать
в обход lease. Текущий Continuum проход не прерывать ради изменения документов.

После checkpoint/освобождения перечитай точный HEAD R и состояние. Протокол:
1. Убедись в отсутствии действующего чужого lease; чистый checkout от R.
2. Lease-only commit L с единственным parent R, уникальным публичным runId,
   owner/baseCommit/acquiredAtUTC/expiresAtUTC, максимум 45 минут.
3. Non-force ref update с expected_sha=R. При конфликте перечитай и останови
   попытку, не делай слепой rebase, повтор или force.
4. Прочитай ref и BACKGROUND обратно: требуется HEAD L, свой runId и срок.
5. Перед renewal/integration/publication снова проверь exact HEAD/runId/deadline;
   оставляй минимум пять минут на checkpoint и проверку результата.
6. Финальный F имеет parent текущего подтверждённого leased HEAD, содержит
   результат, checkpoint/pendingVerification и executionLease:null одним update.
7. После update перечитай ref/SHA/tree/parent. Неизвестный исход выясни чтением;
   не публикуй второй раз из устаревшей папки и не «освобождай» чужой lease.

Только координатор интегрирует и публикует. Помощники возвращают локальные diff,
evidence и blockers, не обновляют shared refs. Процедурный lease не является
секретом, GitHub credential, OS lock или доказанным fencing вредоносного writer.

Чтобы завершать V1, root после безопасного handoff согласует центральную очередь,
release branch и task router. Старый BACKGROUND с nextTask Continuum нельзя
бесконечно исполнять вопреки новому ACTIVE_FOR_V1. Сохранить исследования и
принятые результаты обязательно; перенос приоритета не означает удалить R&D.

## 7. Контракт Production V1 для передачи команды AVERKRON

V1 — self-hosted native X10 для одного объявленного Linux-профиля и доверенного
оператора. Предложенный первый профиль: Ubuntu 24.04 x86_64, Node 22, объявленные
версии/ABI PCRE2/OpenSSL/zlib/libcrypt. Подтверди его фактически; source build
и binary bundle имеют отдельные требования. Не обещай любой Linux или Windows.

Все ворота обязательны:
- Установка опубликованного пакета в новую private prefix от непривилегированного
  пользователя на отдельной совместимой среде; source checkout не нужен runtime.
- Реальный HTTP reverse proxy к приложению, поток/загрузка и выбранный HTTPS
  путь с проверкой сертификата/hostname; публичные admin endpoints закрыты.
- Запуск как законченный сервис на тестовом операторском хосте: контролируемый
  supervisor/service recipe, health/status/logging и проверенный restart.
  Foreground demo с открытым терминалом не завершает промышленный операторский путь.
- Успешное применение managed config, отказ syntax-invalid и unhealthy candidate,
  проверяемый revert, история и явное восстановление поддержанных прерываний.
- Переживание остановки CLI/перезапуска процесса и документированный выбор
  последней подтверждённой конфигурации; старый binding не переносится молча.
- Обновление самого пакета и возврат предыдущего: совместимость state и side-by-side
  либо migration path проверены. Revert приложения не означает downgrade бинарника.
- Нагрузка/slow clients/обрывы/ошибки storage проверены по заранее записанным
  критериям для этого профиля; bounded cleanup и отсутствие необъяснённой утраты данных.
- Нет нерешённых критических дефектов в поддержанном пути. У неподдержанных
  состояний явный отказ/runbook, а не зелёный статус по умолчанию.
- Exact final SHA, clean build, актуальные regression/Unix/feature-off gates,
  provenance и permanent versioned archive с checksums/license/known limits.
- Независимый оператор проходит опубликованный download→install→serve→change→
  fail→revert→restart→upgrade→rollback-package→stop/uninstall маршрут.
- Release notes и AVERKRON /cases/ показывают фактический V1 status и доказательства.
  Повторяемая поставка доступна пользователю, а не только автору в workspace.

Результат не обязан иметь cloud/fleet GUI или LLM. Базовый NGINX сохраняет свои
native возможности; V1 support matrix различает «поддержано этим продуктовым
профилем», «сохранено и проверено в части compatibility fixtures», «ещё не проверено».
HTTP/3, mail, произвольные dynamic modules и весь межплатформенный каталог не
объявляются полностью сертифицированными по факту компиляции.

Общий scope последующих этапов сохраняется явно: расширенная матрица x10/PLAN,
удалённое управление/роли/audit/fleet, connected native console, объяснимые
routing/cache/peer/limit decisions, доказанные workload optimizations и Continuum.
«10×» — проверяемая цель конкретного сценария; это не критерий, которым можно
заменить работающую поставку или рекламу без измерений.

## 8. Последовательность пакетов и зависимости

### G0 — согласовать исполнение и безопасно завершить текущий research checkpoint
Вход: свежий central manifest и exact native HEAD.
Сверь живой lease. Дождись предусмотренного checkpoint без прерывания; проверь
реальные CI текущего cleanup fix, сохрани его narrow acceptance и оставшиеся gates.
Root безопасно записывает ACTIVE_FOR_V1 и release task routing. Старый pending
текст сверяется, а не автоматически считается актуальной ошибкой.
Выход: один координатор, действующий V1 contract, source/release refs и ownership.

### G1 — заморозить V1 release contract и профиль
Объяви supports/unsupported, threat model, service target, health semantics,
resource/time/error thresholds, upgrade/recovery boundaries и тестовый хост.
Сохрани весь широкий scope в отдельном roadmap. Определи показатели до измерений.
Выход: проверяемый RELEASE-CONTRACT, release manifest schema, без неизвестных
«готово потому что прошло много тестов».

### G2 — закончить и опубликовать Local Alpha
Исправь stale Quickstart, установи extracted bundle отдельно, проверь основные
команды, целостность, unknown files/symlink/foreign PID refusals. Добавь полезный
реальный upstream с его health, а не только native demo self-check. Сохрани
первую версионную alpha поставку. Это отдельный законченный этап, статус V1 pending.

### G3 — реальный gateway и операторский сервис V1
Доведи один supported app/proxy/TLS сценарий до эксплуатации вне checkout.
Проверь supervisor recipe в разрешённой тестовой среде, startup/shutdown,
перезапуск, health/status и логирование. Default admin — private Unix/local,
remote доступ не открывается неявно. Если supervisor недоступен в среде,
выбери реально поддержанный профиль вместо фиктивного PASS.
Выход: запускаемый и обслуживаемый gateway, понятная инструкция оператора.

### G4 — update/revert/recovery как полный операторский путь
Проверь application/config change и package upgrade отдельно. Тестируй
invalid config, unhealthy release, pending transaction, failed durable save,
interruption, stale identity/revision, changed libraries и abnormal master exit.
Определи, что recover делает автоматически, а что требует ручной проверки.
Покажи package rollback без переписывания неизвестных пользовательских файлов.
Не обещай атомарный cutover всего трафика или rollback совершённых операций.
Выход: воспроизводимый upgrade и возврат, доказанный state/recovery contract.

### G5 — независимая безопасность и совместимость поддержанного профиля
Threat model: trusted same-UID operator, private prefix и local control.
Same-UID malicious process не изолируется одними hashes. Проверяй ownership,
permissions, symlinks, secret exposure, config dump, socket ACL, bounds и deadlines.
Для любого нового native C patch: исходный counterexample, candidate и
соседние lifetime/event/error paths. Не переписывай протоколы без доказанного
недостатка. Выход: все критические замечания закрыты/профиль сужен явно в contract,
неподдержанные состояния отказаны и объяснены.

### G6 — финальные runtime, нагрузка и восстановление
Заморозь candidate, сборочные входы и acceptance thresholds. Выполни применимые
тесты и не менее одного продолжительного репрезентативного прогона на разрешённом
хосте; плановый первый минимум — 60 минут normal/slow-client сценариев вне
ограниченных CI jobs. Это базовый V1 soak, не доказательство многомесячного SLA.
Время/нагрузку/CPU/RSS/error budget зафиксируй до запуска; не подбирай их ради PASS.
Сравни устойчивость и overhead с корректным baseline, сохрани adverse/A/A данные.
Не требуется маркетинговый speedup; необъяснённую регрессию нельзя скрывать.
Выход: release candidate acceptance с точными bytes/identities и cleanup.

### G7 — поставка и supply chain
Чистая сборка на объявленном профиле, pinned inputs, manifest, VERSION/release
notes, native binary, allowlisted CLI, LICENSE/NOTICE, checksum, SBOM/список
зависимостей и источник security updates. Подпись — только существующим доступным
механизмом с настоящим key management; checksum не называть подписью.
Постоянный GitHub release archive не должен зависеть от 14-day CI retention.
Выход: проверенная версия и воспроизводимая процедура следующего выпуска.

### G8 — промышленный V1 опубликован и принят из опубликованной поставки
Независимый release-path reviewer использует только опубликованные файлы и
документацию, повторяет установку/работу/обновление/возврат и сверяет manifest.
Выполняется разрешённый smoke на операторском тестовом deployment; фактический
deployment/ref записан. Наличие архива без запуска или preview без gateway не PASS.
Release V1 не включает experimental Continuum в production data path.
Выход: V1 ACCEPTED с конкретной версией, SHA, artifacts и оставшимся roadmap.

### G9 — переход к новому AVERKRON
Координатор перечитывает все ворота, фиксирует V1 evidence и откат, оставляет
X10 maintenance/security lane, сохраняет незавершённый R&D с точным nextTask.
Обновляет центральный PORTFOLIO-STATE: завершён конкретный X10 V1, новый AVERKRON
становится основным активным продуктом. Alpha одна не разрешает этот переход.
Следующая очередь: TEXTORA / AI Index → TROVENDI → Replyscope.
Смена фокуса не удаляет X10 и не означает обещание, что вся его широкая программа
уже завершена. Новый дефект безопасности поддержанного V1 обслуживается явно.

## 9. Шесть помощников: полезные роли и ownership

Координатор один. До шести полезных помощников создаются заново по реальным
slots; отсутствие slots означает последовательное выполнение, не выдуманную команду.
Не нагружай всех кодом ради числа агентов. У каждого exact base SHA, пакет,
allowlisted files, ожидаемый выход, deadline и правила cleanup.

| Роль | Задача | Исключительное владение |
|---|---|---|
| 1. Native compatibility | Сохранность ядра/профиля, маленькие native fixes при реальном дефекте, upstream baseline | Назначенные src/auto/conf файлы и связанные native regression fixtures; configure только в отдельном checkout |
| 2. Controller/recovery | Жизненный цикл ревизий, state/journal, apply/revert/recover, service semantics | Назначенные x10/control файлы и controller tests; не alpha CLI и не глобальный BACKGROUND |
| 3. Distribution/operator runtime | install/pack/service/update/uninstall, manifests и поддержанный ABI | Назначенные x10/alpha файлы, build/package scripts и собственные package tests; CI только через координатора |
| 4. Independent end-to-end QA | Реальные user flows, fault/slow-client/TLS cases, итоговая clean install | Отдельные release-path fixtures/reports; runtime автора не правит, ошибки отдаёт владельцу |
| 5. Security/release reviewer | Threat model, secret/permissions/PID/storage/supply-chain review, heldouts | Read-only исходники; собственные review/heldout файлы с отдельными именами; не меняет проверяемые assertions автора |
| 6. Product/DX/docs | Операторская понятность, Quickstart/known limits/release notes, attribution и коммерческие границы | Назначенные release docs и примеры; глобальные планы/бренд AGENTS интегрирует координатор |

Координатор владеет интеграцией, AGENTS, STATUS/PLAN/BACKGROUND, центральным
manifest, workflow changes, branch/ref и release publication. На один файл —
один writer. Если helper 2 и 3 требуют один файл, сначала изменить assignment,
а не разрешить гонку. Общий root Makefile/generated inputs не используются
двумя builds одновременно.

Обязательный prompt каждому помощнику:
«Ты выполняешь [роль] пакета [G]. Прочитай этот CONTINUATION-PROMPT,
CURRENT-STATE и свежие AGENTS/применимые контракты на [exact SHA].
Файлы для записи: [список]. Остальные только чтение. Не делай remote commits,
push, merge, deployment, purchases или schedule changes. Верни diff, команды,
реальные результаты, identities, cleanup, риски и следующий конкретный gate.
При смене HEAD/ownership/deadline останови интеграцию и сообщи координатору.
Не обещай принятия всего X10 по проверке своего участка».

## 10. Команды QA и пределы их доказательства

Перед полной native проверкой подготовь exact profile из свежих BUILD/CI:
```sh
python3 -m venv x10/.build/http3-venv
x10/.build/http3-venv/bin/python -m pip install --require-hashes --only-binary=:all: -r x10/test/http3-baseline.requirements.txt
x10/.build/http3-venv/bin/python -m pip check
python3 -m venv x10/.build/http3-head-venv
x10/.build/http3-head-venv/bin/python -m pip install --require-hashes --only-binary=:all: -r x10/test/http3-head.requirements.txt
x10/.build/http3-head-venv/bin/python -m pip check
bash x10/build.sh --jobs 2
node x10/test/all.mjs --official
```
Зависимости ставит подготовленная разрешённая среда/CI. Не запускай sudo/apt
на чужом production host из-за недостающего локального инструмента.

Обязательные отдельные профили, когда относятся к изменению/выпуску:
```sh
node --test --test-reporter=tap x10/test/proof.test.mjs
node x10/test/control-api-baseline.mjs --transport unix
node x10/test/generations.mjs --transport unix
X10_STATUS_TRANSPORT=unix node --test --test-reporter=tap x10/test/operator-status.test.mjs
bash x10/test/control-disabled.sh --output x10/.build/control-disabled.json
node --test --test-reporter=tap x10/test/alpha.test.mjs
node x10/alpha/cli.mjs pack --output x10/.build/dist/nginx-x10-linux-alpha.tar.gz
```
Pack не перезаписывает существующий output; для нового candidate выбери новый
путь. Наличие API feature-off build — не сертификация всех платформ/ABI.
--provenance-only не выполняет функциональные проверки. Отсутствующий required
HTTP3 client — ошибка подготовки профиля, не успешный skip.

Для изменения Continuum, когда R&D действительно поручен:
```sh
node x10/continuum/check.mjs
node --test --test-reporter=tap x10/continuum/process-handover.test.mjs
node x10/continuum/handshake-check.mjs
node x10/continuum/openssl-probe-check.mjs
```
Добавленные protection/API tests запускай по свежему manifest/документации,
не угадывай имя нового файла из прошлого чата. Исследовательский успех не
заменяет native regression. Для docs-only блока не повторяй дорогой runtime
без новой причины; проверь diff/ссылки/commit message/identity и CI scope.

Для release-path изолируй свободные loopback ports и новый private prefix,
проверь непривилегированный UID. При root-only namespace clean-user gate здесь
не выполнен: используй совместимый существующий CI/host, не запускай его как root
и не меняй production ради имитации успешного теста.

Сохраняй exit status самого теста. Pipeline в tee не должен превращать nonzero
в PASS. После изменения tests/assertions выполни final frozen run; старый
42-case diagnostic не является приёмкой позднейших 44-case bytes.

## 11. Provenance, CI и статусы

Доказательство выпуска содержит:
- source repo/branch/full SHA; tree/parent и native upstream pin;
- implementation SHA отдельно от документационного successor;
- event head отдельно от PR merge checkout и build checkout;
- workflow/run/job/attempt, какие steps действительно выполнены;
- configure/compiler/dependency header и runtime identities, generated input
  hashes/modes, binary hash и supported ABI;
- artifact ID, ZIP digest, tar digest, payload allowlist и expiration;
- команды/метрики/условия/единицы подсчёта, skips/TODO/unexpected failures;
- независимый review, failure controls, cleanup и known limits;
- фактический deployment/runtime и процедура возврата.

Не складывай aggregate groups, nested TAP tests, official assertions и compiled
modules. Успешный metadata scope job не доказывает новый runtime. Каждое значение
«прошло» относится к своей версии и своей единице. CI green на другом SHA —
историческая информация.

Снимок bf7f9aa имеет verified native PR run40085252512, job120846791209:
20/20 suites, controller77 TAP, alpha37 TAP, official1105 strictPASS/
25SKIP/1expectedTODO-fail/0unexpectedFAIL. Event head bf7f9aa, merge/build
cc627b03590fa2e171a5d9117263ff5e3ddf44ce. Research run40085252538,
job120846786246 реально выполнил21/7/27/44. Подробности — соседние файлы.
Это сняло конкретную внешнюю CI неизвестность снимка; published BACKGROUND ещё
мог иметь pending. Новый координатор фиксирует reconciliation только под lease.

Inherited F5 CLA failure отдельно от native/research результата. По CI.md причина
связана с pristine default master и publisher integration. Не подписывай соглашение
за владельца, не добавляй publisher secret и не скрывай failure ради зелёной
картинки. Оформи собственную release/check policy и точный residual issue.

## 12. Эксплуатация, секреты и возврат

Default loopback/private Unix control. Если V1 поддерживает remote management,
оно требует отдельной принятой auth/authz/audit/TLS модели; bearer в public
ссылке/браузерном persistent storage недопустим. Console CORS не заменяет ACL.

Health проверяет ровно заявленную readiness функцию; native self-check не
доказывает здоровье приложения. GET health не должен совершать бизнес-операции.
State/journal/backups/config dump могут содержать секреты: публичная evidence
сохраняет allowlisted counts/hashes/границы, не raw configurations, traffic keys,
host/process/namespace identifiers, сырые runtime logs или credential URLs.

Не удаляй старые known-good package/config/state до принятия нового.
Для package update используй проверенный side-by-side/private prefix путь или
принятую migration procedure; проверь совместимость и обратимость до переключения.
Откат кода не откатывает базу данных, платежи, отправленные сообщения и запросы,
которые кандидат уже успел обслужить. Старое содержимое после target I/O не
является безопасным универсальным rollback TLS state.

SIGKILL/crash может оставить orphan workers; alpha отказывает automatic
restart/uninstall в faulted состоянии. V1 обязан иметь проверенный runbook
проверки точных принадлежащих процессов и безопасного восстановления; не killall.
Generation metadata — учёт master, а не worker readiness, listener-close ACK
или доказательство полного drain. Verified PID→signal race не объявлять
устранённой без нового OS-level механизма и проверки.

## 13. Continuum: сохранить утверждённую программу, не блокируя V1 навсегда

Продолжение R&D делается только по текущему назначению после безопасного checkpoint
и в отдельном opt-in контуре. До следующих gates сохраняй явный отказ:
- полный bounded semantic/API inventory фактического established TLS state;
- исходные auth/ALPN/Finished/session/exporter/resumption obligations;
- protection/syscall cleanup failures, expiry/revocation и ownership;
- reviewed semantic export/import в fresh target library objects;
- независимое исключительное reader/writer право на тот же transport;
- distinct TLS/record code, реальное завершение старого кода без скрытого helper;
- held-out third-version adapter и adverse partial I/O/KeyUpdate/backpressure;
- HTTP/WebSocket state adapters, затем opt-in native NGINX integration;
- pause/retirement/CPU/RSS/error/unsupported comparisons с корректным drain baseline.

C0 synthetic vectors, C1 handshake, C2a read-only probes, защищённая дополнительная
копия и socket passing — разные достижения. Ни одно по отдельности не migration.
Исходный SSL/EVP heap, Node internals и compiler temporaries не защищаются
автоматически свойствами отдельной locked mapping. SIGKILL wipe неизвестен.
Не вводи экспериментальную криптографию в V1 hot path.

Эти gates не отменяются и не объявляются выполненными. Они сохраняются как
R&D acceptance после отдельного production V1. При фундаментальном препятствии
фиксируется отрицательный результат и пересмотр механизма, а не fake PASS,
смена термина или бесконечное расширение расходов.

## 14. Коммерческий путь

Первая ценность V1 — пригодный self-hosted gateway и сокращение операционных
ошибок в поддержанном процессе установки/изменения/возврата. Клиент получает
конкретный инструмент; модель/консоль не продаются как доказательство надежности.

Покупателей, выручки, production SLA и подтверждённой готовности платить в
снимке нет. Коммерческие гипотезы поддержки, verified releases и fleet
описаны в существующих continuum/COMMERCIAL.md и ECONOMICS.md; их цены и
внутренние бюджетные предположения здесь повторно не публикуются. Это не
подтверждённый спрос, действующие тарифы или доход.
Без завершённой TLS migration не продавать seamless live-code upgrade.

Сначала закончить инструмент, документацию и воспроизводимые примеры. Затем
проверять пользу относительно бесплатного NGINX/drain/других подходящих решений,
считать полный труд внедрения/поддержки, CAC/churn и регулярную себестоимость.
Отдельно считать разовые внедрения и recurring subscription; ARR не равен прибыли.

Не ждать клиента для завершения техпоставки и не выдумывать клиентов/кейсы.
Для страницы AVERKRON используй собственный проект и фактическую стадию выпуска,
без фиктивной истории заказов. Основные product/release docs готовятся понятно,
английская версия допустима для международной аудитории; точность важнее объёма.

## 15. Автономия, деньги, расписание и отчёты

Рутинные чтения, разработка, исправления, проверки, локальные файлы и безопасные
Git checkpoints внутри поручения уже разрешены. Не спрашивай повторно, можно ли
исправить баг или продолжать следующий согласованный пакет. При ограничении
инструмента ищи материально безопасный доступный путь, а блокер записывай точно.

Используй существующие явно разрешённые ресурсы. Финансовые ограничения
сверяй с действующими доступными координатору правилами и существующими
COMMERCIAL/ECONOMICS; не публикуй внутренние суммы в новом публичном handoff.
Не создавай платные подписки/GPU/инфраструктуру/рекламу/контракты или рассылки
другим людям по своему усмотрению. Не меняй соседние проекты, DNS, REG.RU,
production или личные аккаунты внутри research прохода без соответствующего
поручения.

Закрытие компьютера пользователя не означает постоянную жизнь помощников.
Существующая automation — периодическое возобновление, которое перечитывает
центральный pinned prompt и свежий checkpoint. Запись в JSON не доказывает,
что scheduler действительно настроен. Root проверяет/обновляет именно существующее
расписание доступным инструментом после принятия нового поручения, не создаёт
дубли и не прерывает чужой текущий проход. Worker сам расписание не меняет.

Историческое60h окно в BACKGROUND заканчивается26.10.2026 19:17:36UTC;
report-only до20:17:36UTC. Этот документ не подменяет его бессрочным обещанием.
Сверяй актуальную явную политику владельца/центрального координатора и ограничения
сессии; при достижении дедлайна сохрани результат и честный handoff, не скрывай
остановку и не оставляй бесконтрольные fixtures.

После каждого содержательного пакета:
1. Результат для пользователя, exact SHA и фактические файлы.
2. Пройденные команды/единицы/границы, CI/artifact/deployment отдельно.
3. Отказы, adverse evidence, skips/TODO и cleanup.
4. Что ещё блокирует alpha/V1/R&D, следующий gate и ответственный.
5. Реальные затраты и состояние lease.
6. Обновлённый GATES/central state с доказательствами; без процентов готовности.

Коммит проверяется .github/scripts/commit-msg-check.pl: нужен пустой diagnostics,
а не только exit0; описание до72символов в строке. Финальный отчёт владельцу
краткий; подробности живут в Git. Не утверждай «всё работает», пока не пройден
полный опубликованный пользовательский путь.

## 16. Первое задание следующему координатору

Не начинай с переписывания native ядра, новой витрины или роста числа тестов.
Сначала перечитай current central/ref/lease, безопасно сохрани принятый
Continuum protection/API checkpoint, reconcile exact CI и зафиксируй G0/G1.
Затем закончи G2 alpha и двигайся последовательно к G8 Production V1.
Если текущий lease ещё жив, подготовь независимый read-only release gap review
и останови запись в shared branch до предусмотренного handoff.

Не переходи на AVERKRON по готовности одной alpha. Не держи все остальные
продукты бесконечно в ожидании полного Continuum: переход происходит по
явно принятому Production V1 contract и G9, с сохранением исследовательского scope.

## Дополнительное чтение перед публикацией — 24.10.2026, 15:00 Самара

Для event head `66a65419a04ec5e4ff3604dec214d553a85f2a1b` проверены run40087363660/native job120852957405 и run40087363637/research job120852955113: completed/success, реальные шаги присутствуют. Это обновляет историческое наблюдение in_progress в срезе10:49UTC. В этом дополнительном чтении новый binary artifact не скачивался и checkout merge SHA не устанавливался; хеши/счётчики bf7f9aa не переносятся на него. Это проверка текущих jobs, а не приёмка Production V1. Дальнейшие действия сверять по свежему HEAD и собственному lease.
