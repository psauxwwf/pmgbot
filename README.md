# pmgbot

`pmgbot` is a daemon for Proxmox Mail Gateway (PMG) spam quarantine automation.

It reads field-based regexp rules from `pmgbot.yaml` or `pmgbot.override.yaml`, loads spam quarantine entries through `pmgsh`, and automatically delivers or deletes matching messages.

## How It Works

The daemon runs this cycle:

1. Reads configuration from `pmgbot.yaml`, or `pmgbot.override.yaml` if `pmgbot.yaml` does not exist.
2. Gets current spam quarantine entries:

```bash
sudo pmgsh get /quarantine/spam --starttime $(date --date='-30 days' +%s) --endtime $(date +%s)
```

3. Matches every quarantine message against `rules` from top to bottom.
4. Applies the first matching rule action by quarantine message ID.
5. Skips messages that do not match any rule.
6. Waits for the next `daemon.cron` schedule and repeats the cycle.

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

Save a detailed Markdown report for `run` or `check`:

```bash
pmgbot check --config pmgbot.yaml --report
pmgbot run --config pmgbot.yaml --report
```

The report file name is generated automatically in the current directory, for example `pmgbot-check-report-20260822-083015-123456789.md`. When `--report` is used, stdout includes a final `report | path: ...` line. The Markdown report includes summary metrics, rule/sender/receiver/subject counts, skipped messages, and a final table with all planned or applied `deliver`/`delete` actions and their parameters.

`run` and `check` stream a human-readable action report to stdout as messages are processed:

```text
subject | id
envelope_sender | from | receiver | action
---
next subject | next id
next envelope_sender | next from | next receiver | next action
---
summary | total: 10 | deliver: 2 | delete: 3 | skip: 5 | errors: 0
```

Every message row is followed by `---`. If `run` cannot apply an action, the row ends with `| error: ...`.
Action is printed as `[delete:RULE_NAME]` or `[deliver:RULE_NAME]`.
The `run` command also writes structured JSON logs to `log_path` when it is configured, but does not print those logs to the terminal. The `check` command prints only the stdout report. The `daemon` command writes text logs to the terminal and JSON logs to `log_path` when it is configured.

Print detailed quarantine content by message ID as JSON:

```bash
pmgbot get --config pmgbot.yaml C1R1691568T97183293
```

The output includes PMG `/quarantine/content` fields plus `raw`, read from `/var/spool/pmg/<file>`. The `raw` field is printed last.

Analyze current PMG spam subjects, envelope senders, and From headers:

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

Without `--json`, `analyze` and `generate` fetch the current spam quarantine through `pmgsh` using the configured timeout and `sudo` setting. With `--json`, they read a saved PMG spam dump from disk instead. For both commands, `--min-count` is based on the total number of messages with the same subject, summed across all envelope sender and From combinations.

The generator does not edit `pmgbot.yaml`. It prints a `rules:` YAML fragment for review. By default it creates one exact-match rule per subject seen at least twice, then adds all senders for that subject under `envelope_sender` or `from` as OR patterns. Use `--min-count` and `--action` to tune the output.

Output format:

```text
subject | count | script | lang
envelope_sender | from | id | count | action
---
next subject | count | script | lang
next envelope_sender | next from | next id | count | action
---
summary | total: 10 | deliver: 2 | delete: 3 | remain: 5
```

Sender action is `skip` when no rule matches, or `[delete:RULE_NAME]` / `[deliver:RULE_NAME]` when a rule matches.
When a sender row aggregates multiple messages, IDs are comma-separated inside brackets, for example `[id1,id2,id3]`. If a loaded JSON dump has no message IDs, the ID column is `-`.
The summary is calculated across all loaded spam messages, not only subjects shown after `--min-count` filtering.

Run continuously as a daemon:

```bash
pmgbot daemon --config pmgbot.yaml
```

Create a default config file:

```bash
pmgbot --save-config --config pmgbot.yaml
```

`--save-config` belongs only to the root command and is not available on subcommands. Without an explicit `--config`, runtime commands load `pmgbot.yaml` first and fall back to `pmgbot.override.yaml` only when `pmgbot.yaml` is absent.

## Configuration

Example `pmgbot.yaml`:

```yaml
log_level: info
log_path: ""
sudo: true
daemon:
  cron: "0 8 * * *"
  timeout: 10m0s
rules:
  # Важно про логику списков:
  # - каждый элемент YAML-списка через "-" задает вариант ИЛИ;
  # - несколько regexp у одного поля тоже задают ИЛИ;
  # - несколько полей внутри одного элемента "-" задают И.
  # - префикс [!] инвертирует один regexp: '[!]Mail Delivery' = НЕ содержит Mail Delivery.
  #   Значения с [!] нужно брать в YAML-кавычки.
  # - count в группе задает условие на число писем из текущего спама,
  #   которые подходят под остальные условия этой же группы.
  #   Поддерживаются операторы: 3 или '>=3', '>3', '<3', '<=3'.
  #   Минимальное значение count: 1.
  # - pattern '[===]' сравнивает поле со значением этого же поля у текущего письма.
  #   Например subject: '[===]' + count: 3 = темы, повторившиеся 3 или больше раз.
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

  # Примеры count:
  # - subject: '[===]' + count: 3 = 3 или больше писем с такой же темой;
  # - count: 3 или '>=3' = 3 или больше таких писем;
  # - count: '>3' = больше 3 таких писем;
  # - count: '<3' = меньше 3 таких писем;
  # - count: '<=3' = 3 или меньше таких писем.
  - name: Delete repeated subjects by count examples
    action: delete
    when:
      - subject: '[===]'
        count: 3
      - subject: '^TEST_GE$'
        count: '>=3'
      - subject: '^TEST_GT$'
        count: '>3'
      - subject: '^TEST_LE$'
        count: '<=3'
      - subject: '^TEST_LT$'
        count: '<3'

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
- `daemon.cron`: cron schedule for daemon cycles; the default `0 8 * * *` runs once per day at 08:00.
- `daemon.timeout`: timeout for each PMG operation phase.
- `rules`: ordered list of named matching rules.
- `rules[].name`: human-readable rule name used in logs.
- `rules[].action`: `deliver` or `delete`.
- `rules[].when`: condition groups for this rule.
- `rules[].when[].count`: optional comparison against the number of messages in the current spam load that match the other fields in the same condition group.

Durations use Go duration syntax, for example `30m`, `1h`, or `10m0s`. A bare number is treated as minutes. `daemon.cron` uses standard 5-field cron syntax by default, for example `0 8 * * *` for every day at 08:00; 6-field cron with seconds is also accepted. `pmgbot daemon` runs one cycle immediately at startup and then follows `daemon.cron`; `pmgbot run --config pmgbot.yaml` runs a single cycle immediately and exits. `pmgbot check --config pmgbot.yaml` prints matching messages with the action that would be applied, but does not deliver or delete anything.

## Matching Fields

`rules` is an ordered list. A message matches the first rule where any `when` group matches. In rule conditions, YAML list items written with `-` mean `OR`: multiple `when` groups are alternatives, and multiple regexps under one field are alternatives too. Fields inside one `when` list item are combined with `AND`: every listed field must match at least one of its regexps.

`count` is a special condition-group key, not a PMG message field and not a regexp. When present, it compares the number of messages in the current spam load that match the other fields in the same `when` group. If `count` is omitted, it does not affect matching.

`[===]` is a special pattern value. It compares a field with the same field of the current message instead of compiling a regexp. For example, `subject: '[===]'` means "same subject as the current message". Combined with `count`, it can match repeated values in the current spam load.

The minimum `count` value is `1`. A bare number means `>=N`. Quote operator values in YAML, especially values starting with `>` or `<`.

Supported `count` forms:

| What to require       | Count syntax         |
| --------------------- | -------------------- |
| 3 or more messages    | `count: 3` or `count: '>=3'` |
| More than 3 messages  | `count: '>3'`        |
| Fewer than 3 messages | `count: '<3'`        |
| 3 or fewer messages   | `count: '<=3'`       |

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

This rule deletes messages with subject `TEST` only when the current spam load contains at least 3 messages whose subject matches `^TEST$`:

```yaml
rules:
  - name: Delete repeated TEST subjects
    action: delete
    when:
      - subject: '^TEST$'
        count: 3
```

This rule deletes messages when their subject appears at least 3 times in the current spam load. This is the rule equivalent of `analyze --min-count 3` by subject:

```yaml
rules:
  - name: Delete repeated subjects
    action: delete
    when:
      - subject: '[===]'
        count: 3
```

These rules show strict and non-strict count comparisons:

```yaml
rules:
  - name: Delete repeated subjects by count examples
    action: delete
    when:
      - subject: '[===]'
        count: 3
      - subject: '^TEST_GE$'
        count: '>=3'
      - subject: '^TEST_GT$'
        count: '>3'
      - subject: '^TEST_LE$'
        count: '<=3'
      - subject: '^TEST_LT$'
        count: '<3'
```

Rule keys can use these PMG quarantine JSON text fields returned by `/quarantine/spam`:

- `envelope_sender`
- `from`
- `receiver`
- `subject`

Rules can also use computed fields derived from `subject`:

- `subject_script`: dominant subject script, one of `latin`, `cyrillic`, `cjk`, `mixed`, or `unknown`.
- `subject_language`: detected subject language as a lower-case ISO 639-1 code such as `en`, `ru`, or `es`; returns `unknown` when detection is not reliable.

Numeric PMG fields such as `bytes`, `spamlevel`, and `time` are parsed from PMG but are not available as rule keys.

Unknown rule keys are rejected during config validation. The special `count` key is allowed only as a condition-group threshold.

Matching is case-sensitive by default. Use `(?i)` inside a regexp for case-insensitive matching.

Use `[!]` as the inversion prefix. Prefix a regexp with `[!]` to invert only that pattern. For example, `subject: '[!]Mail Delivery'` matches subjects that do not contain `Mail Delivery` anywhere, because the inner regexp `Mail Delivery` is not anchored. Quote inverted patterns in YAML because they start with `[`.

Inversion is per regexp, not per field or rule. If a field has multiple regexps, they are still alternatives: the field matches when any listed pattern matches, including any inverted pattern whose inner regexp does not match.

For example, delete Latin-script subjects only when they also match the same sender group:

```yaml
rules:
  - name: Delete latin spam subjects
    action: delete
    when:
      - envelope_sender: '@example\.com$'
        subject_script: '^latin$'
```

Delete reliably detected English subjects:

```yaml
rules:
  - name: Delete English subjects
    action: delete
    when:
      - subject_language: '^en$'
```

Delete English subjects except delivery notifications:

```yaml
rules:
  - name: Delete English subjects except delivery notifications
    action: delete
    when:
      - subject_script: '^latin$'
        subject_language: '^en$'
        subject: '[!]Mail Delivery'
```

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

Rule patterns use Go `regexp` syntax, also known as RE2 regular expression syntax. Useful basics: `.*` means any characters, `\.` means a literal dot, `^` means start of string, `$` means end of string, and `(?i)` enables case-insensitive matching. The pmgbot-specific inversion prefix is `[!]`; it is not part of Go regexp syntax and is stripped before compiling the regexp.

The pmgbot-specific same-value token is `[===]`; it is not part of Go regexp syntax and is handled before regexp compilation. Use it when a field should match the same field value as the current message, usually together with `count`.

### Inversion

| What to match                                      | Pattern                           |
| -------------------------------------------------- | --------------------------------- |
| Subject does not contain `Mail Delivery`           | `subject: '[!]Mail Delivery'`     |
| Subject does not start with `Positive Technologies` | `subject: '[!]^Positive Technologies'` |
| Case-insensitive subject does not contain `invoice` | `subject: '[!](?i)invoice'`       |

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
