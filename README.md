# Ergo Blackout

Ergo Blackout — это Rust-инструмент для включения проверяемого режима сетевой изоляции.

Цель проекта — не обещать магическую “полную автономию”, а управляемо перекрывать сетевые каналы на уровне конкретной платформы: firewall rules, routing, DNS, сетевые интерфейсы, слушающие сокеты и системные сервисы.

## Первый этап

Главная целевая платформа для MVP — Linux.

Минимальный рабочий набор:

```bash
cargo run -- blackout
cargo run -- status
cargo run -- restore
cargo run -- dry-run
```

`blackout` включает режим изоляции.

`status` показывает текущее сетевое состояние и активные правила.

`restore` откатывает изменения.

`dry-run` показывает, что будет сделано, без применения изменений.

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
cargo run -- status
cargo run -- restore
cargo run -- dry-run
```

`blackout` enables isolation mode.

`status` shows the current network state and active rules.

`restore` rolls back applied changes.

`dry-run` shows what would be done without applying changes.

## Platforms

The project should be cross-platform, but implementation will happen step by step:

1. Linux / Unix-like systems.
2. Windows.
3. Android.
4. iOS.

On mobile platforms, available functionality will depend on system restrictions, root access, VPN APIs, or other approved mechanisms.
# ergo_blackout
