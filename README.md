# Exfil Analyzer

Форензик-анализатор: безопасно детонирует программу с GitHub в изоляции и выдаёт человеку
понятную сводку — была ли попытка утечки секретов, что пыталось **докачаться** и что
**прочитать/отправить**. НЕ блокер. Observe-only.

## Архитектура (v3.0.2, honeynet-centric)

```
github.com/owner/repo
   └─► bin/scan.sh
        (1) java-analyzer  — СТАТИКА: читает исходники → manifest.json («заявление»)
        (2) sandbox        — ДЕТОНАЦИЯ: hardened-Docker-контейнер, весь egress → honeynet
            honeynet       — FakeNet/INetSim (фейк-сервисы + DNS-sinkhole) + mitmproxy (TLS)
            rust-observer  — тонкий aya-сенсор на хосте: openat(canary)/execve/connect-metadata
        (3) java-analyzer  — КОРРЕЛЯЦИЯ: сшивает сеть+dns+http+файлы+процессы → отчёт (CLI+HTML)
```

Правда наблюдения живёт на **сетевой границе песочницы** (honeynet+MITM), а не в kernel-taint:
сетевой namespace контейнера обойти нельзя (`io_uring`/`sendfile` не помогают), а MITM с нашим CA
расшифровывает обычный TLS → канарейку видно в payload. Cert pinning / QUIC → `opaque`.

**Хост неприкосновенен:** изоляция строго поконтейнерно; сеть сервера (SSH/Tailscale) не трогаем.

## Контракты (`schema/`)

Раздельные JSONL-потоки, сшиваются по `run_id`/`sample_id`:
`network` · `dns` · `http` · `files` · `proc`.

## Статус

Скелет (структура + контракты). Кода ещё нет. Реализация — по фазам Ф0→Ф4.
Дизайн: канонический план v3.0.2. Код пишет Codex, ревью — Claude.

## Запуск (целевой)

```
ssh myserver
bin/scan.sh <git-url>      # всегда observe-only + honeynet (fail-closed)
```
