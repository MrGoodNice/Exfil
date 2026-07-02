# Exfil Analyzer

Форензик-анализатор: безопасно детонирует программу с GitHub в изоляции и выдаёт человеку
понятную сводку — была ли попытка утечки секретов, что пыталось **докачаться** и что
**прочитать/отправить**. НЕ блокер. Observe-only.

## Архитектура (v3.0.3, honeynet-centric)

```
github.com/owner/repo
   └─► bin/scan.sh
        (1) java-analyzer  — СТАТИКА: читает исходники → manifest.json («заявление»)
        (2) sandbox        — ДЕТОНАЦИЯ: hardened-Docker-контейнер, весь egress → honeynet
            honeynet       — свой тонкий Go-стек: DNS-sinkhole + HTTP/TLS-терминатор (+ per-run CA)
            rust-observer  — тонкий aya-сенсор на хосте: openat(canary)/execve/connect-metadata
        (3) java-analyzer  — КОРРЕЛЯЦИЯ: сшивает сеть+dns+http+файлы+процессы → отчёт (CLI+HTML)
```

Стек ядра: **Go** (honeynet — статические distroless-бинари, без Python-рантайма), **Rust/aya**
(eBPF-сенсор), **Java** (главный код: корреляция + отчёт). Linux-only.

Правда наблюдения живёт на **сетевой границе песочницы** (honeynet+MITM), а не в kernel-taint:
сетевой namespace контейнера обойти нельзя (`io_uring`/`sendfile` не помогают), а MITM с нашим CA
расшифровывает обычный TLS → канарейку видно в payload. Cert pinning / QUIC → `opaque`.

**Хост неприкосновенен:** изоляция строго поконтейнерно; сеть сервера (SSH/Tailscale) не трогаем.

## Контракты (`schema/`)

Раздельные JSONL-потоки, сшиваются по `run_id`/`sample_id`:
`network` · `dns` · `http` · `files` · `proc`.

## Статус

Реализация по фазам Ф0→Ф4. Код пишет Codex, ревью и прогон тестов — Claude.
Каждая фаза закрывается только после реального прогона своего гейта.

- **Ф0 — фундамент** ✅ контракты, fail-closed песочница, генератор канареек, сэмплы
- **Ф1 — honeynet (Go)** ✅ DNS-sinkhole + HTTP/TLS-терминатор + CA, `network/dns/http.jsonl`,
  L4↔L7-джойн по `flow_id`, матч канарейки в расшифрованном payload
- **Ф2 — aya-сенсор (Rust)** ✅ `openat`(canary) + `execve`(дерево) + `connect`(dst/pid),
  cgroup-scoped → `files/proc/network.jsonl`; загрузка доказана на ядре 6.18
- **Ф3 — java-мозг** 🔨 Ф3.0 ✅ (ingestion + EventCorrelator: сшивка honeynet↔aya, цепочка-доказательство);
  осталось: классификатор докачек, отчёт CLI+HTML, статик-манифест
- **Ф4 — полировка** ⏳

## Запуск (целевой)

```
bin/scan.sh <git-url>      # всегда observe-only + honeynet (fail-closed)
```

Разработка — локально (Linux, ядро ≥5.8 с BTF). Детонация незнакомых репозиториев — только в
одноразовой Linux-VM, не на рабочей машине.
