# Ergo Blackout

Ergo Blackout — это Rust-инструмент для включения проверяемого режима сетевой изоляции.

Цель проекта — не обещать магическую “полную автономию”, а управляемо перекрывать сетевые каналы на уровне конкретной платформы: firewall rules, routing, DNS, сетевые интерфейсы, слушающие сокеты и системные сервисы.

## Первый этап

Главная целевая платформа для MVP — Linux.

Минимальный рабочий набор:

```bash
cargo run -- blackout
cargo run -- blackout --mode soft
cargo run -- blackout --mode hard --i-understand-this-may-cut-ssh --apply
cargo run -- blackout --mode allowlist --allow-tcp 22 --apply
cargo run -- blackout --apply
cargo run -- status
cargo run -- verify
cargo run -- inspect
cargo run -- restore
cargo run -- restore --apply
cargo run -- dry-run
```

`blackout` показывает план включения режима изоляции без изменения системы.

`blackout --apply` применяет Linux nftables blackout rules.

`status` кратко показывает состояние Ergo Blackout: inactive / verified / drifted.

`verify` подробно проверяет, что nftables rules стоят как ожидается.

`inspect` показывает информацию о системе, backend-ах, интерфейсах, маршрутах, listening ports и активных подключениях.

`restore` показывает план отката без изменения системы.

`restore --apply` удаляет только nftables table, созданную Ergo Blackout.

`dry-run` показывает, что будет сделано, без применения изменений.

Режимы blackout:

1. `soft` блокирует новые соединения, но оставляет существующие.
2. `hard` блокирует всё кроме loopback и требует явного подтверждения перед `--apply`.
3. `allowlist` блокирует всё кроме явно разрешенных TCP/UDP портов.

## Платформы

Проект должен быть кроссплатформенным, но реализация будет идти поэтапно:

1. Linux / Unix-like системы.
2. Windows.
3. Android.
4. iOS.

На мобильных платформах возможности будут зависеть от системных ограничений, root-доступа, VPN API или других разрешенных механизмов.

---

eng

Ergo Blackout is a Rust tool for enabling a verifiable network isolation mode.

The goal is not to promise magical “full autonomy”, but to controllably block network channels at the level of each specific platform: firewall rules, routing, DNS, network interfaces, listening sockets, and system services.

## First Stage

The main target platform for the MVP is Linux.

Minimal working command set:

```bash
cargo run -- blackout
cargo run -- blackout --mode soft
cargo run -- blackout --mode hard --i-understand-this-may-cut-ssh --apply
cargo run -- blackout --mode allowlist --allow-tcp 22 --apply
cargo run -- blackout --apply
cargo run -- status
cargo run -- verify
cargo run -- inspect
cargo run -- restore
cargo run -- restore --apply
cargo run -- dry-run
```

`blackout` shows the isolation plan without changing the system.

`blackout --apply` applies Linux nftables blackout rules.

`status` briefly shows the Ergo Blackout state: inactive / verified / drifted.

`verify` checks in detail that nftables rules match the expected plan.

`inspect` shows system information, backend availability, interfaces, routes, listening ports, and active connections.

`restore` shows the rollback plan without changing the system.

`restore --apply` removes only the nftables table created by Ergo Blackout.

`dry-run` shows what would be done without applying changes.

Blackout modes:

1. `soft` blocks new connections but keeps existing ones alive.
2. `hard` blocks everything except loopback and requires explicit confirmation before `--apply`.
3. `allowlist` blocks everything except explicitly allowed TCP/UDP ports.

## Platforms

The project should be cross-platform, but implementation will happen step by step:

1. Linux / Unix-like systems.
2. Windows.
3. Android.
4. iOS.

On mobile platforms, available functionality will depend on system restrictions, root access, VPN APIs, or other approved mechanisms.
