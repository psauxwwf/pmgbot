# pmgbot

`pmgbot` is a daemon for Proxmox Mail Gateway (PMG) spam quarantine automation.

It reads field-based regexp rules from `pmgbot.yaml`, loads spam quarantine entries through `pmgsh`, and automatically delivers or deletes matching messages.

## How It Works

The daemon runs this cycle:

1. Reads configuration from `pmgbot.yaml`.
2. Gets current spam quarantine entries:

```bash
pmgsh get /quarantine/spam
```

3. Matches every quarantine message against `rules` from top to bottom.
4. Applies the first matching rule action by quarantine message ID.
5. Skips messages that do not match any rule.
6. Waits for `daemon.every` and repeats the cycle.

If multiple rules match one message, the first rule in `rules` wins.

PMG output may start with `200 OK`; `pmgbot` ignores that prefix before parsing the JSON array.

## Command

Run one cycle and exit:

```bash
pmgbot run --config pmgbot.yaml
```

Check what would be delivered or deleted without applying actions:

```bash
pmgbot check --config pmgbot.yaml
```

Analyze current PMG spam subjects and their senders:

```bash
pmgbot analyze --config pmgbot.yaml
```

Only show subjects with at least 20 total messages across all senders:

```bash
pmgbot analyze --config pmgbot.yaml --min-count 20
```

Analyze a saved PMG spam JSON dump instead of calling `pmgsh`:

```bash
pmgbot analyze --config pmgbot.yaml --json spam.json
```

Generate candidate delete rules from current PMG spam quarantine:

```bash
pmgbot generate --config pmgbot.yaml
```

Generate candidate rules from a saved PMG spam JSON dump instead of calling `pmgsh`:

```bash
pmgbot generate --config pmgbot.yaml --json spam.json
```

Without `--json`, `analyze` and `generate` fetch the current spam quarantine through `pmgsh` using the configured timeout and `sudo` setting. With `--json`, they read a saved PMG spam dump from disk instead. For both commands, `--min-count` is based on the total number of messages with the same subject, summed across all senders.

The generator does not edit `pmgbot.yaml`. It prints a `rules:` YAML fragment for review. By default it creates one exact-match rule per subject seen at least twice, then adds all senders for that subject under `envelope_sender` or `from` as OR patterns. Use `--min-count` and `--action` to tune the output.

Output format:

```text
subject - count
envelope_sender - count
---
next subject - count
next envelope_sender - count
```

Run continuously as a daemon:

```bash
pmgbot daemon --config pmgbot.yaml
```

Create a default config file:

```bash
pmgbot --save-config --config pmgbot.yaml
```

## Configuration

Example `pmgbot.yaml`:

```yaml
log_level: info
log_path: ""
sudo: true
daemon:
  every: 15m0s
  timeout: 10m0s
rules:
  # Важно про логику списков:
  # - каждый элемент YAML-списка через "-" задает вариант ИЛИ;
  # - несколько regexp у одного поля тоже задают ИЛИ;
  # - несколько полей внутри одного элемента "-" задают И.
  # Пример: "- from: A; receiver: [B, C]" = from A И (receiver B ИЛИ receiver C).

  # Один field + несколько regexp: subject A ИЛИ subject B.
  - name: Deliver explicitly allowed subjects
    action: deliver
    when:
      - subject:
          - '^\[ALLOW\]'
          - "(?i)важный отчет"

  # envelope_sender И (subject A ИЛИ subject B).
  - name: Delete webmaster registration or payment confirmations
    action: delete
    when:
      - envelope_sender: '^webmaster@rc\.ffff\.ru$'
        subject:
          - '^\[SPAM\]: Зарегистрировался новый пользователь$'
          - '^\[SPAM\]: Платеж .* на сумму .* руб\. подтвержден$'

  # (sender A ИЛИ B) И (receiver A ИЛИ B) И (subject A ИЛИ B).
  - name: Delete payment phishing to finance mailboxes
    action: delete
    when:
      - envelope_sender:
          - '^[^@]+@payment-notice\.example\.ru$'
          - '^[^@]+@bank-alert\.example\.net$'
        receiver:
          - '^accounting@example\.com$'
          - '^finance@example\.com$'
        subject:
          - "(?i)payment confirmation required"
          - "(?i)подтвердите платеж"
```

Fields:

- `log_level`: log level, supports `debug`, `info`, `warn`, and `error`.
- `log_path`: path to a JSON log file; if empty, logs are written only to stderr.
- `sudo`: run external commands through `sudo`.
- `daemon.every`: how often to run the daemon cycle.
- `daemon.timeout`: timeout for each PMG operation phase.
- `rules`: ordered list of named matching rules.
- `rules[].name`: human-readable rule name used in logs.
- `rules[].action`: `deliver` or `delete`.
- `rules[].when`: condition groups for this rule.

Durations use Go duration syntax, for example `30m`, `1h`, or `10m0s`. A bare number is treated as minutes. `daemon.every` is used only by `pmgbot daemon`; `pmgbot run --config pmgbot.yaml` runs a single cycle immediately and exits. `pmgbot check --config pmgbot.yaml` logs only matching messages with the action that would be applied, but does not deliver or delete anything.

## Matching Fields

`rules` is an ordered list. A message matches the first rule where any `when` group matches. In rule conditions, YAML list items written with `-` mean `OR`: multiple `when` groups are alternatives, and multiple regexps under one field are alternatives too. Fields inside one `when` list item are combined with `AND`: every listed field must match at least one of its regexps.

This rule deletes messages where `envelope_sender` matches and `subject` matches either listed regexp:

```yaml
rules:
  - name: Delete webmaster notifications
    action: delete
    when:
      - envelope_sender: '^webmaster@rc\.ffff\.ru$'
        subject:
          - '^\[SPAM\]: Зарегистрировался новый пользователь$'
          - '^\[SPAM\]: Платеж .* на сумму .* руб\. подтвержден$'
```

Rule keys must match PMG quarantine JSON field names returned by `/quarantine/spam`:

- `envelope_sender`
- `from`
- `receiver`
- `subject`

Only these text fields are supported for matching. Numeric fields such as `bytes`, `spamlevel`, and `time` are parsed from PMG but are not available as rule keys.

Unknown rule keys are rejected during config validation.

Matching is case-sensitive by default. Use `(?i)` inside a regexp for case-insensitive matching.

## Actions

Deliver a matched message:

```bash
pmgsh create /quarantine/content --id C1R33T82611969 --action deliver
```

Delete a matched message:

```bash
pmgsh create /quarantine/content --id C1R33T82611969 --action delete
```

The `id` is the quarantine API ID returned by `/quarantine/spam`.

## Regexp Examples

Rule patterns use Go `regexp` syntax, also known as RE2 regular expression syntax. Useful basics: `.*` means any characters, `\.` means a literal dot, `^` means start of string, `$` means end of string, and `(?i)` enables case-insensitive matching.

### Sender Domains

| What to match                                                  | Pattern                          |
| -------------------------------------------------------------- | -------------------------------- |
| Any direct email at `domain.com`, equivalent to `*@domain.com` | `^[^@]+@domain\.com$`            |
| Any email ending with `@domain.com`                            | `@domain\.com$`                  |
| Any email at `domain.com` or `example.com`                     | `^[^@]+@(domain                  | example)\.com$` |
| Any subdomain of `domain.com`, for example `a@sub.domain.com`  | `^[^@]+@[^@]+\.domain\.com$`     |
| `domain.com` and any of its subdomains                         | `^[^@]+@([^.@]+\.)*domain\.com$` |
| Any `.ru` domain                                               | `^[^@]+@[^@]+\.ru$`              |
| Any `.com` or `.net` domain                                    | `^[^@]+@[^@]+\.(com              | net)$`          |

### Specific Emails

| What to match                              | Pattern                    |
| ------------------------------------------ | -------------------------- |
| Only `email@bob.com`                       | `^email@bob\.com$`         |
| Only `admin@domain.com`                    | `^admin@domain\.com$`      |
| `admin@domain.com` or `support@domain.com` | `^(admin                   | support)@domain\.com$` |
| Any `no-reply` sender                      | `^no-reply@[^@]+$`         |
| Local part starts with `bounce-`           | `^bounce-[^@]*@[^@]+$`     |
| Local part contains `mailer`               | `^[^@]*mailer[^@]*@[^@]+$` |

### Subjects

| What to match                   | Pattern       |
| ------------------------------- | ------------- |
| Case-insensitive `invoice`      | `(?i)invoice` |
| Case-insensitive crypto/lottery | `(?i)crypto   | lottery` |
| Subject starts with `[SPAM]`    | `^\[SPAM\]`   |

## Build And Test

Build:

```bash
task build
```

Run tests directly:

```bash
go test ./...
```

`task test` in this project runs `go fix ./...` before `go test ./...`.

## Systemd

The repository includes an example `pmgbot.service` unit file.

Expected installation layout:

```text
/opt/pmgbot/pmgbot
/opt/pmgbot/pmgbot.yaml
```

The unit runs:

```bash
/opt/pmgbot/pmgbot daemon --config /opt/pmgbot/pmgbot.yaml
```
