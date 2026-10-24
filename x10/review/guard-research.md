# Guard: проверяемая гипотеза R&D

Статус: проект исследования для следующего этапа после local Linux alpha.
Первый разрабатываемый срез — детерминированный tenant/cache kernel.
Интеграции LLM пока нет; этот RFC не является отчётом об успешном испытании.

## Цель и граница утверждения

По изменению конфигурации предлагать риски, контракты и последовательности
запросов; исполнять их на настоящем NGINX и сохранять воспроизводимый
контрпример. Предложенное исправление принимается только по независимым
детерминированным проверкам. Клиент может использовать свой бинарник NGINX.

Рабочая гипотеза: AI может находить полезные, отсутствующие в replay,
последовательности запросов для проверки взаимодействия auth и cache после
изменения конфигурации, сокращая ручную подготовку сценариев. Возможный вклад —
качество поиска и отбраковки исправлений при заданном бюджете. Новизна этой
комбинации и её преимущество перед простыми шаблонами пока не установлены.

## Ближайшие работы: на что нельзя заявлять новизну

| Первичный источник | Уже существующий подход | Следствие для Guard |
| --- | --- | --- |
| [ACtests: Testing Access-Control Configuration Changes for Web Applications](https://arxiv.org/html/2505.12770v1) | Выполнение приложения, включая NGINX, до/после config change; сравнение allow/deny; replay и синтез запросов; изолированная mini environment. | Реальный NGINX, отрицательные запросы и change-impact testing уже известны. Синтез требует источников subjects/objects/actions; авторы обсуждают ограничения покрытия и trimming. |
| [CornerCase, Microsoft Research](https://www.microsoft.com/en-us/research/publication/cornercase-automated-extremal-testing-of-protocol-implementations-using-llms/) | LLM извлекает ограничения из спецификаций; генератор строит boundary inputs; differential execution ищет расхождения реализаций. | Общая цепочка AI → тесты → differential execution не является нашим изобретением. |
| [Gixy](https://github.com/yandex/gixy), [Gixy-Next](https://github.com/MegaManSec/Gixy-Next) | Статический анализ NGINX и набор проверок security/configuration, включая inheritance, alias и proxy headers. | Нужен baseline статических проверок; нельзя объявлять новое предупреждение новым классом анализа без сравнения. |
| [Speedscale replay](https://docs.speedscale.com/concepts/replay/), [локальный proxymock и CI](https://speedscale.com/) | Capture/replay, dependency mocks, сравнение ответов, latency и CI gate. | Сам replay, self-hosted/local запуск и отчёт о response diff не создают отличия. |
| [Cornetto, ETH Zürich](https://nsg.ethz.ch/publications/2026-05-05-benchmarking-llm-driven-network-configuration-repair-20-500-11850-799709/) | Оценка LLM repair сетевых конфигураций независимой formal verification; наблюдаются регрессии исправлений. | AI repair с внешним проверяющим механизмом тоже имеет prior art; наши runtime checks не равны formal verification. |

Эти источники подтверждают близкие подходы, а не отсутствие у них любых
stateful/cache возможностей. Вывод о незанятой нише по ним делать нельзя.

## Контур исполнения

1. **AI proposal.** Модель видит разрешённые config bundles, diff и профиль
   бинарника; возвращает типизированные risk/contract/request-sequence/patch
   proposals с привязкой к строкам. Произвольные shell-команды не исполняются.
2. **Строгий контракт.** Schema ограничивает actors, методы, endpoints, headers,
   преобразования и бюджет. Политика берётся из версионированных требований
   владельца; догадка AI остаётся предложением, пока не стала таким требованием.
   Само расхождение старой и новой версии ещё не означает дефект.
3. **Native execution.** Проверяются `nginx -t`, identity бинарника и config
   inputs. Baseline/candidate запускаются с отдельными prefix/cache/temp/logs
   и одинаковыми fixture dependencies. Первый срез — private loopback,
   контролируемые upstream и synthetic data, без обращения к production.
4. **Witness.** Независимый oracle сопоставляет реальные ответы с контрактом;
   сохраняются порядок запросов, reset/seed, actor markers, upstream trace,
   исходные/нормализованные ответы, конфиги, hashes и команда повторения.
   Уменьшение последовательности допустимо, только пока ошибка воспроизводится.
5. **Repair.** Модель может предложить ограниченный config patch. Проверяющий
   механизм повторяет исходный witness, контрольные сценарии и удержанные
   regressions. AI не выставляет PASS и не может переписать oracle/контракт.
6. **Результат.** PASS/FAIL/UNSUPPORTED/ERROR определяет runner; отчёт отделяет
   нарушение контракта от инфраструктурной ошибки. Автоматического воздействия
   на production, публикации конфигурации или reload production здесь нет.

Результат — воспроизводимое свидетельство на проверенных последовательностях,
а не доказательство безопасности всех запросов. Доверие к старой версии также
не подразумевается: oracle должен обнаруживать нарушение обеими версиями.

## Первый вертикальный срез: tenant/cache sequence

Управляемый upstream возвращает различимые synthetic markers пользователей A/B.
Две конфигурации одного native binary различаются ключом/политикой cache.
Контракт требует одновременно tenant isolation и сохранение разрешённого cache.

- Для каждой версии начать с отдельного пустого cache; выполнить A → B → A → B
  к одному URI. Повторить B → A → B → A с новым пустым cache.
- Ответ каждому actor содержит только его marker. Повтор своего запроса даёт
  ожидаемый HIT; upstream trace подтверждает, какие запросы реально исполнялись.
- Baseline соответствует контракту; дефектный candidate демонстрирует утечку.
  No-op и неэффективное исправление продолжают давать FAIL.
- Правильное исправление проходит isolation и positive cache controls.
  Отключение всего cache не выполняет контракт сохранения cache; оно может быть
  допустимой отдельной mitigation policy, но не эквивалентным исправлением.
- По каждому исходу есть повтор без модели. Ошибка fixture или потеря ответа
  не засчитывается как найденная утечка. Все дочерние процессы убираются bounded.

Это проверка детерминированного исполнительного ядра. Пока запросы и patches
заданы разработчиком, нельзя называть результат AI discovery или AI repair.
Реальные auth flows, credentials и приложения добавляются отдельным срезом.

## Эксперимент, который может опровергнуть гипотезу

**Корпус.** Зафиксировать корректные конфигурации, известные дефектные изменения
и допустимые изменения поведения. Разделить по семействам конфигураций, а не
только по строкам запросов: held-out includes/routes/cache keys не должны быть
копиями демонстрации. Записать config/fixture seeds, budgets и binary identity;
удержанные oracle cases не давать модели, генераторам и процессу настройки.

**Сравнения при одинаковом бюджете:** deterministic sequence templates;
применимые Gixy checks; naive replay без новых запросов; AI proposals с тем же
native runner. Отдельная ablation — AI без config diff. Gixy outside its rule
scope помечать как неприменимое сравнение, а не как ошибку инструмента.

**Метрики:** пропущенные известные утечки; доля корректных изменений, ошибочно
заблокированных gate; доля повторяемых witnesses; нарушения positive controls
после repair; принятые неэффективные repairs; runtime и CPU/memory;
число native executions, tokens и фактическая стоимость модели.
Показывать абсолютные counts/denominators и seeds, вариативность запусков,
timeouts/unsupported отдельно. Не скрывать неблагоприятные результаты.

**Переход к AI.** Сначала kernel стабильно различает дефект/no-op/fix и сохраняет
positive controls. Затем подключается реальный model API с записью версии,
параметров, prompt/output hashes и бюджета. После этого проверяются unseen
конфигурации: даёт ли AI дополнительный результат относительно templates/replay
при сопоставимых затратах и false blocks. Отсутствие преимущества — допустимый
итог, при котором оставляем полезный deterministic checker.

## Что пока unsupported или неизвестно

Произвольные клиентские bundles, third-party modules, njs/Lua, внешние auth/DB,
небезопасные request replays, HTTP/2/3, TLS/client identity, reload races,
многоузловой cache, distributed state, Windows и production isolation требуют
отдельных адаптеров и evidence. Loopback не изолирует вредоносный same-UID код.
`nginx -T` не заменяет production state; его содержимое может включать секреты.
Покрытие sequences, качество AI proposals и repair, переносимость контрактов
и коммерческая полезность ещё не измерены. Нет claim «world first», «все
запросы безопасны», «10×» или готовности к автономному production управлению.
