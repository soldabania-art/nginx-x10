# X10: ограниченный выпуск V1

**Сейчас: G1 release contract определён; выпуска Production V1 ещё нет.**

- [Контракт](RELEASE-CONTRACT.md) задаёт полезный операторский результат,
  threat model, service target, два вида rollback и критерии приёмки.
- [profile.json](profile.json) закрепляет кандидат
  `ubuntu-24.04-x86_64-node22-v1` и prospective thresholds до измерений.
- [release-record.schema.json](release-record.schema.json) и
  [checker](check-release-record.mjs) проверяют release record. Schema задаёт
  необходимую форму; checker дополнительно связывает version/tag/canonical URLs,
  source/build/evidence refs и порядок gates. Schema сама не выполняет все
  эти проверки. Согласованная запись не доказывает реальный запуск или готовность.
- [G0–G9](../continuation-2026-10-24/GATES.json) различают контракт, Local Alpha,
  operated service, recovery, frozen runtime/soak, постоянную поставку,
  независимый replay и разрешённую портфельную передачу.

Runtime alpha описан отдельно в [alpha/README](../alpha/README.md).
Его foreground/demo self-check и CI artifact не равны service/app readiness
или постоянному V1. Инструкция [QUICKSTART](../QUICKSTART.md) использует текущую development ветку
с фиксацией exact checkout; постоянного принятого release ref пока нет.
Здесь намеренно нет придуманной команды скачивания ещё не выпущенного пакета.

Следующая полезная поставка — G2: исправленная инструкция, настоящий upstream
с его readiness, независимая установка extracted bundle и постоянная alpha.
Затем G3–G8 по контракту. Continuum сохраняется в [R&D PLAN](../continuum/PLAN.md)
и остаётся opt-in исследованием вне production data path.

## Проверка подготовленной записи

Из корня checkout, подставив свой существующий JSON-файл:

```sh
node x10/release/check-release-record.mjs release-record.json
```

CLI принимает ровно один regular file до262144bytes, отказывает symlink
вместо самого файла и некорректному вводу. Exit0 означает только допустимую и согласованную декларацию;
exit1 — отказ. Вывод сохраняет `scope: declared-record-validation-only`,
`evidenceAuthenticated: false`, `productionAccepted: false` даже для корректной
записи. Checker не скачивает evidence, не запускает пакет, не удостоверяет подпись
и не даёт разрешение на release/deployment. Принятие G8 требует независимых
фактических проверок опубликованной поставки по контракту.

### Полный bounded receipt текущего native job

Для каждого `build.ci[].executedSteps` текущая schema требует от36 до64
записей. Прежний предел32 не вмещал фактические36 шагов native job.
Сокращать receipt до выбранного подмножества, чтобы пройти ограничение,
нельзя: checker требует все36 имён из `REQUIRED_NATIVE_CI_STEPS` в их
наблюдённом порядке. Список закреплён в [checker](check-release-record.mjs)
и включает setup/checkout/Node, все текущие contract/refusal проверки,
сборку и native regressions, TLS/Unix/feature-off, package/checksum/archive,
реальный user-service, сохранение evidence/архива, post-actions и completion.

Первая запись должна быть `Set up job`, последняя — `Complete job`.
Все имена должны быть уникальны, conclusion каждого шага и самого job —
`success`. Пропуск любого обязательного текущего шага, усечение или нарушение
порядка отвергаются. Дополнительные фактически выполненные шаги допустимы
только между этими границами, с уникальными именами и успешным conclusion,
при сохранении порядка всех36 обязательных имён и общего предела64.
Не переименовывайте записи и не добавляйте придуманные успешные шаги.
Checker проверяет форму декларации и порядок имён; исходный полный job transcript
должен отдельно сверяться с настоящим exact run/job/attempt.

Event head, фактический checkout PR merge, build checkout и artifact identity
сохраняются раздельно. Все CI entries одной записи должны соответствовать
объявленному build checkout; push и PR с различными checkout нельзя смешивать
под одной build identity. Failed/skipped шаги не становятся успешными из-за
того, что другой event прошёл. Исторические receipts и их прежние количества
сохраняют свой exact SHA и область приёмки; ужесточённый текущий контракт
не разрешает дописывать в них новые проверки или переобъявлять историю.

Даже полный согласованный36–64-шаговый список остаётся декларацией.
`evidenceAuthenticated:false` и `productionAccepted:false` сохраняются:
checker не обращается к GitHub, не удостоверяет transcript/артефакт и
не доказывает фактический runtime или готовность выпуска.


## Проверка exact CI контракта G1

Контракт и declaration checker implementation `80629638` прошли отдельный
обязательный hosted step:35 checks на Node22 в каждом из двух native runs,
плюс20/20 native groups. [Квитанция](../evidence/v1-release-contract-hosted.json)
сохраняет фактические jobs/artifacts, skips и границы доказательства.
Research push пропустил runtime; это не новая приёмка исследовательского кода.

Это приёмка формы и согласованности деклараций. Профиль остаётся
DECLARED_NOT_ACCEPTED: service, clean nonroot target,60-minute soak, постоянный
alpha/V1 archive и весь опубликованный operator path ещё требуют G2–G8.
Следующий пакет — настоящий upstream/readiness и независимый extracted-bundle
маршрут G2. Валидный JSON по-прежнему не подтверждает подлинность evidence
и не разрешает выпуск или переход к другому продукту.


## Проверка alpha архива до распаковки

`verify-alpha-archive.mjs` проверяет ограниченный формат текущего alpha pack,
не распаковывая и не запуская payload. Передайте SHA256 из отдельно проверенного
источника, а не из того же недоверенного скачивания:

```sh
node x10/release/verify-alpha-archive.mjs \
  --archive nginx-x10-linux-alpha.tar.gz --sha256 VERIFIED_SHA256
```

CLI сначала сравнивает digest сжатых bytes, затем проверяет ограниченный gzip/tar
и точный состав bundle. Отказываются ссылки, неизвестные и повторные записи,
небезопасные пути и несогласованные payload hashes/sizes/modes. Результат —
проверка согласованности bytes с указанным hash, а не подпись, доверие издателю,
безопасность программы или разрешение выполнять бинарник. Успех не подтверждает
ABI, clean target install, service/TLS, постоянную публикацию либо Production V1.

CI выполняет отдельные отрицательные проверки и проверяет фактически созданный
alpha archive. Обычный CI artifact имеет ограниченный retention; это не постоянный
GitHub Release. В текущем подключённом GitHub инструменте нет операции создания
Release/загрузки release assets; публикация и независимый published-file replay
остаются открыты. Новые credentials или расширение workflow permissions не
создаются ради обхода этого ограничения.


## Supported-path review and archive identity types

The [supported-path review](SUPPORTED-PATH-REVIEW.md) records explicit supported,
refused and still-unknown operator outcomes. The pre-extraction archive verifier
candidate now requires primitive string HEX/REV identities/checksums; malformed
JSON arrays cannot become source identities through regex coercion. Both schema1
and schema2 remain supported. Local synthetic-archive tests do not extract or
execute payload, authenticate an issuer, or accept a release. Exact new hosted
verification remains pending. Controller record-read bounds and session/inventory
capacity are separate open findings; full G4/G5/G7/V1 remains unaccepted.
