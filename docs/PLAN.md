# PLAN (зеркало)

Канонический детальный план: **v3.0.2** (honeynet-centric, observe-only), ведётся у мейнтейнера
в `~/.claude/plans/fluffy-weaving-bonbon.md`. Здесь — краткое зеркало для контекста репозитория.

## Принцип

Точка наблюдения — на **сетевой границе песочницы** (honeynet + mitmproxy), не в kernel-taint.
Java заявляет (статика) → детонация проверяет заявление → человеко-читаемый отчёт.

## Дорожная карта

- **Ф0** — фундамент: скелет (структура + 5 схем), Gradle+Cargo-скелеты, `run-sandboxed.sh`
  (hardened Docker+honeynet, fail-closed), per-run канарейки, 3 сэмпла, первый commit.
- **Ф1** — honeynet + сетевая правда: FakeNet/INetSim + mitmproxy(+CA), весь egress завёрнут →
  `network/dns/http.jsonl`. CA-injection per-runtime; pinning/QUIC → `opaque`.
- **Ф2** — тонкий aya-сенсор: `openat`(canary)+`execve`+`connect`-metadata (строго metadata,
  без taint/block), scoped по cgroup → `files/proc/network.jsonl`.
- **Ф3** — Java-корреляция + отчёт: склейка honeynet↔aya_connect (`SO_ORIGINAL_DST`), сверка с
  manifest, severity, `attempted` vs `observed`, CLI+HTML.
- **Ф4** — полировка.

## Инженерные принципы (кратко)

Честертонов забор → характеризационный/спец-тест ПЕРЕД правкой → минимальный диф → ноль
галлюцинированных API → по одному изменению за раз → не копировать референсы слепо.

## Роли

Код пишет **Codex 5.5**; **Claude — ревьюер**. Хост неприкосновенен (изоляция поконтейнерно).
