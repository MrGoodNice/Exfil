# Phase B — Implementation Brief (для Codex)

**Источник истины:** `~/.claude/plans/fluffy-weaving-bonbon.md` **v3.0.3** (honeynet-centric, observe-only).
Этот файл — исполнимый порядок сборки. Если что-то расходится — прав канонический план, спроси ревью.

**Где:** проект-репо `exfil-analyzer` (push в GitHub `MrGoodNice/exfil-analyzer`). Детонация/eBPF-прогоны — на сервере `ssh myserver` (Linux, BTF, Docker). **Пуш после КАЖДОГО куска.**
**Роли:** код — Codex; ревью — Claude.

---

## 🚫 Как НЕ галлюцинировать (ОБЯЗАТЕЛЬНЫЙ протокол)

Главный риск проекта — выдуманный API/крейт/флаг/путь, который «выглядит правдоподобно». Правила, без исключений:

1. **Ни одного символа из памяти.** Перед использованием ЛЮБОГО внешнего символа (функция aya, hook mitmproxy, флаг Docker, зависимость Cargo/Gradle) — ОТКРОЙ реальный код референса или официальную доку нужной версии и скопируй ТОЧНУЮ сигнатуру. Не «я помню, что в aya есть RingBuf::reserve» — а `grep -rn "fn reserve" ~/refs/aya`.
2. **Проверка существования перед ссылкой.** Любой путь/репо/файл — через `test -e`, `ls`, `grep`, или HTTP 200, до того как на него сослался. (Урок `guardian_shell`: один символ → 404 при реальном проекте.)
3. **Компиляция — единственное доказательство «реальности».** Символ не существует, пока `cargo build`/`gradle build` его не разрезолвил. Не компилируется → API был галлюцинацией → чини чтением реального исходника, НЕ подбором другого имени наугад.
4. **Версии зафиксированы.** Каждая зависимость — точная версия. API дрейфует между версиями; читай доку/исходник ИМЕННО этой версии, не «latest по памяти».
5. **Один символ — один источник.** На каждый внешний вызов в коде оставляй комментарий-леджер: `// ref: snoop snoop-ebpf/src/maps.rs:12 (RingBuf)`. Не можешь указать источник (file:line или URL доки) → ты гадаешь → не пиши.
6. **Характеризационный тест перед портом.** Копируешь реальный код референса — сперва тест, фиксирующий его поведение; не можешь сделать тест зелёным → ты НЕ понял код → стоп, перечитай (правило Честертона).
7. **Смотри тесты самого референса.** Тесты реф-репо показывают РЕАЛЬНОЕ использование API — бери употребление оттуда, не из головы.
8. **Минимальный приращиваемый шаг.** Один внешний вызов → компиляция → тест → коммит. Не пакетируй 10 непроверенных API-вызовов: при поломке виноват последний символ, легко атрибутировать.
9. **Не уверен — TODO + спроси, НЕ выдумывай.** `// TODO: verify aya RingBuf API` честно; выдуманный вызов, случайно скомпилившийся, — мина.
10. **Не доверяй сгенерированному коду (включая свой).** Любой сниппет от LLM — гипотеза, проверяемая компиляцией+тестом+исходником, никогда не факт. Это и есть этос проекта: не доверять непроверенному выводу.

**Если сомнение остаётся — НЕ коммить, вынеси вопрос в ревью Claude с конкретикой («в aya версии X не нашёл Y, чем заменить?»).**

---

## Железные правила (на каждый кусок)

1. **Тест ПЕРЕД кодом.** Характеризационный — если портируешь реальный код референса; спец-тест — если пишешь свой по паттерну. Ни строки без теста.
2. **Минимальный диф, по одному изменению за раз.** Каждое компилируется и проходит тесты.
3. **Не копировать слепо** — берём паттерн под наш дизайн; host-changing части НЕ берём.
4. **Хост неприкосновенен.** Сеть хоста (SSH/Tailscale) не трогаем. Всё fail-closed.
5. **Цикл куска:** тест → минимальный код → `cargo/gradle build`+тест зелёные → показать Claude → (после ок) commit + push.

Референсы (клоны Шага A, цитаты проверены 12/12): `snoop` `mitmproxy` `flare-fakenet-ng` `package-analysis` `guarddog` `canarytokens`.

---

## Ф0.0 — финализация контрактов (schema/) [Claude вносит]

- `network.schema.json`: +`flow_id` (`["string","null"]`, назначает honeynet; связывает network↔http; у `aya_connect` пока null).
- `http.schema.json`: +`flow_id`; `canary_match` сканирует **заголовки И тело**.
- `dns.schema.json`: +`canary_match[]` (DNS-label exfil).
- **NEW** `manifest.schema.json` — «заявление» Java-статики: `{repo, generated_at, analyzer_version, items:[{type, value, evidence, capability, threat, confidence, suspicious}]}` (taxonomy guarddog).
- **NEW** `canary.schema.json` — per-run каталог: `{run_id, generated_at, secrets:[{secret_id, type, path, env_name?, match_token}]}`.
- Тест: все схемы валидны (jsonschema в CI).

## Ф0.1 — скелеты, что компилируются [Codex]

- `rust-observer/` — Cargo workspace по snoop split: `snoop/snoop-common/snoop-ebpf` ([`snoop/Cargo.toml:1`]). Пустые программы, что собираются.
- `java-analyzer/` — Gradle-скелет (OpenJDK 21 на сервере есть).
- Тулчейны на сервере: `rustup` + `bpf-linker` + `clang`. Проверить `cargo build`.
- Тест: `cargo build` и `gradle build` зелёные.

## Ф0.2 — fail-closed песочница [Codex] — 🔴 КРИТИЧЕСКИЙ ГЕЙТ

- `sandbox/run-sandboxed.sh` — **hardened Docker** (БЕЗ gVisor): `--cap-drop ALL`, seccomp, `--userns`, `no-new-privileges`, read-only+tmpfs, non-root, pids/mem/cpu лимиты; весь egress → honeynet; **fail-closed**.
  - Паттерн: `package-analysis` iface Init/Run/Clean/CopyInto/CopyBack ([`internal/sandbox/sandbox.go:83`]), lifecycle+env ([`sandbox.go:295`]).
  - **НЕ копировать** host-network init: bridge+`iptables-restore` ([`internal/sandbox/init.go:114`]).
- `sandbox/cleanup.sh` — идемпотентный сброс.
- Спец-тест (гейтит Claude на сервере): из контейнера публичный+Tailscale IP недостижимы; `ssh myserver` жив; cleanup без остаточных bridge/nft. **Пока не зелёное — Ф1+ не начинаем.**

## Ф0.3 — per-run канарейки [Codex]

- `sandbox/canary-gen.sh` → каталог по `canary.schema.json`. Паттерн `canarytokens`: id 25 симв ([`constants.py:17`]), типы ([`models/common.py:92`]), форматы AWS/kubeconfig ([`models/aws_keys.py:20`], [`kubeconfig.py:99`]). **Крипто-стойкий RNG**.
- Спец-тест: per-run уникальность; форматы валидны; секреты редактируются в отчёте; без внешних запросов.

## Ф0.4 — 3 сэмпла [Codex]

`benign` (качает публичный файл), `malicious-direct` (canary_rsa + POST), `malicious-child` (canary_rsa → child curl).

---

## Ф1 — honeynet + сетевая правда (ПЕРВЫЙ по ценности) [Codex]

- `sandbox/honeynet/`: DNS-sinkhole ([`fakenet/listeners/DNSListener.py:101`]), custom HTTP ([`HTTPListener.py:63`]), config-driven listeners ([`fakenet/fakenet.py:86`]). **НЕ берём** Diverter/iptables/`RedirectAllTraffic` ([`test/template.ini:43`]).
- `mitmproxy`-аддон → `http.jsonl` `source=honeynet`, `upstream:false`: request hook ([`examples/addons/http-reply-from-proxy.py:6`]), dns hook ([`dns-simple.py:19`]), `SO_ORIGINAL_DST` ([`mitmproxy/platform/linux.py:5`]). caveat: `tcp_message` по `recv`-кускам ([`tcp-simple.py:1`]).
- **CA-trust injection per-runtime**: система (`SSL_CERT_FILE`/`update-ca-certificates`), Node (`NODE_EXTRA_CA_CERTS`), Python (`REQUESTS_CA_BUNDLE`). pinning/QUIC → `opaque`.
- `flow_id` назначает honeynet.
- Спец-тесты: HTTPS-POST curl/python/node расшифрован + канарейка сматчена; pinning → `opaque`; benign → синтетика; host-сеть не изменилась.

## Ф2 — тонкий aya-сенсор [Codex]

- `rust-observer/bpf/`: `openat.rs` (+`is_canary` по пути; паттерн `snoop` [`sys_enter.rs:26`]/[`sys_exit.rs:26`], maps/ringbuf [`maps.rs:12`]), `execve.rs` (дерево/ppid, follow-child fork/clone), `connect.rs` (**только metadata**, оригинальный dst; `retval` НЕ сигнал блока/taint). `src/cgroup.rs` — scope ([`snoop/src/container.rs:36`]).
- Пишет `files/proc/network(source=aya_connect).jsonl`; +`tgid/ppid/cgroup/run_id/source`.
- Тест: портируешь кусок `sys_enter/sys_exit/container/json` → **характеризационный**; иначе спец-тест. Минимум: `openat`→path; `execve`→child-edge; `connect`→original dst+pid; child-exfil → child-pid.

## Ф3 — Java-корреляция + отчёт [Codex]

- `ManifestBuilder.java` — статика `guarddog`: capability+threat→risk ([`risk_engine.py:86`]); seed-правила (`capability-network-outbound.yar`, `threat-filesystem-read.yar`, `threat-runtime-environment-read.yar`); FP-в-комментах ([`analyzer.py:149`]). Static-score = **feature**, НЕ вердикт.
- `EventCorrelator.java` — **склейка honeynet↔aya_connect** по `run_id + original dst + proto` в окне (`SO_ORIGINAL_DST`), связь через `flow_id` → **ОДНО** egress с `pid + host/path + canary_match`. Несматченные: aya без honeynet → network-only; honeynet без aya → `pid:null`.
- `DownloadClassifier.java` — legit vs suspicious; `attempted` vs `observed`.
- `ReportRenderer.java` — CLI+HTML; цепочка `open(canary_rsa)[pid X] → exec curl → POST evil.com (канарейка в теле)`; честные оговорки.
- Спец-тесты: цепочка собрана; **ровно одно** egress после джойна; legit/suspicious; снапшот HTML/CLI.

## Ф4 — полировка

Обфускация-эвристики, honeynet второго этажа, HTML-полиш.

---

## `bin/` + Acceptance

- `bin/scan.sh <git-url>` — оркестратор (honeynet по умолчанию); smoke на benign. `bin/cleanup.sh` — идемпотентный.
- **Fail-closed:** контейнер не достаёт публичный+Tailscale IP; host SSH жив; cleanup чист.
- TLS: canary матчится в теле где CA доверен; pinning/QUIC честно `opaque`.
- aya видит `openat/execve` гостя (подтверждение, что hardened Docker — верный выбор, не gVisor).
- Отчёт человеко-читаем, решает человек.
