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
или постоянному V1. Инструкция [QUICKSTART](../QUICKSTART.md) пока содержит
исторический development ref; G2 должен исправить её на принятый exact release.
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
